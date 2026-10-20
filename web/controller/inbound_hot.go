package controller

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/session"
)

// The dedicated integration endpoints are intentionally single-inbound and
// admin-only. Resellers must use the priced account-creation workflow.
func (a *InboundController) bindHotInbound(c *gin.Context) (*model.Inbound, error) {
	user := session.GetLoginUser(c)
	if user == nil || user.IsReseller {
		return nil, errors.New("hot provisioning requires an administrator")
	}
	data := &model.Inbound{}
	if err := c.ShouldBind(data); err != nil {
		return nil, err
	}
	if !a.callerOwnsInbound(c, data.Id) {
		return nil, errNotOwned
	}
	ids, explicit := postedMembershipIds(c, data.Id)
	if explicit && (len(ids) != 1 || ids[0] != data.Id) {
		return nil, errors.New("hot provisioning supports only the addressed inbound")
	}
	return data, nil
}

func (a *InboundController) addInboundClientHot(c *gin.Context) {
	data, err := a.bindHotInbound(c)
	if err == nil {
		err = a.inboundService.AddInboundClientHot(data)
	}
	if err != nil {
		jsonObj(c, nil, err)
		return
	}
	jsonObj(c, gin.H{"applied": true, "noRestart": true}, nil)
}

func (a *InboundController) addInboundPeerHot(c *gin.Context) {
	data, err := a.bindHotInbound(c)
	if err == nil {
		err = a.inboundService.AddInboundPeerHot(data)
	}
	if err != nil {
		jsonObj(c, nil, err)
		return
	}
	jsonObj(c, gin.H{"applied": true, "noRestart": true}, nil)
}
