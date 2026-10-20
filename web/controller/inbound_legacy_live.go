package controller

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
)

// Keep legacy authorization, pricing and membership projection, but acknowledge
// kernel account creation only after targeted live application. The admission
// guard stays held from before charging until routing has been acknowledged.
func (a *InboundController) addInboundClientLive(c *gin.Context, data *model.Inbound, membershipIDs []int, explicit bool, admission *service.LegacyClientAddition) {
	fail := func(err error) {
		if admission.Persisted() {
			err = fmt.Errorf("account saved but live activation is incomplete; retry the same request: %w", err)
		}
		jsonMsgObj(c, I18nWeb(c, "somethingWentWrong"), gin.H{"persisted": admission.Persisted(), "applied": false}, err)
	}
	if !admission.Persisted() {
		ticket, err := resellerService.PrepareClientCreate(session.GetLoginUser(c), data)
		if err != nil {
			fail(err)
			return
		}
		if err := admission.Persist(data); err != nil {
			// Refund only a failed database write. Once persisted, the same durable
			// receipt resumes activation without issuing another reservation.
			if !admission.Persisted() {
				if rerr := resellerService.Rollback(ticket); rerr != nil {
					logger.Warning("rolling back a reseller charge whose client write failed: ", rerr)
				}
			}
			fail(err)
			return
		}
	}
	if !admission.Projected() {
		if err := accountService.SyncInboundAccounts(database.GetDB(), data.Id); err != nil {
			fail(err)
			return
		}
		for _, email := range postedClientEmails(data) {
			if _, err := a.applyClientMemberships(c, email, data.Id, membershipIDs, explicit); err != nil {
				fail(err)
				return
			}
		}
		if err := admission.MarkProjected(); err != nil {
			fail(err)
			return
		}
	}
	if err := admission.Apply(); err != nil {
		fail(err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientAddSuccess"), gin.H{"applied": true, "noRestart": true}, nil)
}
