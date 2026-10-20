package model

// LegacyClientAdmission records the durable stages of one legacy client-add
// request. It lets an exact retry finish activation without charging again.
// ClientIDs maps normalized emails to their persisted client_traffics primary
// keys, so a deleted and recreated account cannot inherit an earlier receipt.
// The receipt carries no credentials and is never serialized to API responses.
type LegacyClientAdmission struct {
	RequestKey string `json:"-" gorm:"primaryKey;size:64"`
	UserId     int    `json:"-" gorm:"not null"`
	InboundId  int    `json:"-" gorm:"not null"`
	ClientIDs  string `json:"-" gorm:"column:client_ids;type:text;not null"`
	Projected  bool   `json:"-" gorm:"not null;default:false"`
	Applied    bool   `json:"-" gorm:"not null;default:false"`
}
