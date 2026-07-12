package node

import "time"

type RelaySubscriptionGroup struct {
	Id              int64      `gorm:"primaryKey"`
	ServerId        int64      `gorm:"not null;index;comment:Server ID"`
	Name            string     `gorm:"type:varchar(120);not null;comment:Group name"`
	URL             string     `gorm:"type:varchar(1024);not null;comment:Subscription URL"`
	Enabled         bool       `gorm:"not null;default:true;comment:Enabled"`
	AutoUpdate      bool       `gorm:"not null;default:false;comment:Automatic update"`
	UpdateInterval  int        `gorm:"not null;default:86400;comment:Update interval seconds"`
	ListenPortStart int        `gorm:"not null;default:643;comment:Listen port start"`
	ListenPortStep  int        `gorm:"not null;default:100;comment:Listen port step"`
	Rules           string     `gorm:"type:longtext;not null;comment:Last applied relay rules JSON"`
	LastStatus      string     `gorm:"type:varchar(20);not null;default:'never';comment:Last update status"`
	LastError       string     `gorm:"type:text;comment:Last update error"`
	LastUpdatedAt   *time.Time `gorm:"comment:Last successful update time"`
	CreatedAt       time.Time  `gorm:"<-:create"`
	UpdatedAt       time.Time
}

func (*RelaySubscriptionGroup) TableName() string { return "relay_subscription_groups" }
