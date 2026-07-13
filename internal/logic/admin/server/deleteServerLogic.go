package server

import (
	"context"

	"github.com/perfect-panel/server/internal/model/node"
	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/xerr"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DeleteServerLogic struct {
	logger.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

// NewDeleteServerLogic Delete Server
func NewDeleteServerLogic(ctx context.Context, svcCtx *svc.ServiceContext) *DeleteServerLogic {
	return &DeleteServerLogic{
		Logger: logger.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *DeleteServerLogic) DeleteServer(req *types.DeleteServerRequest) error {
	nodeStore := l.svcCtx.Store.Node()
	if err := nodeStore.Transaction(l.ctx, func(db *gorm.DB) error {
		if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", req.Id).First(&node.Server{}).Error; err != nil {
			return err
		}
		if err := deleteServerManagedStateTx(db, req.Id); err != nil {
			return err
		}
		if err := nodeStore.DeleteServer(l.ctx, req.Id, db); err != nil {
			return err
		}
		return nodeStore.DeleteServerConfigOverride(l.ctx, req.Id, db)
	}); err != nil {
		l.Errorw("[DeleteServer] Delete Server Error: ", logger.Field("error", err.Error()))
		return errors.Wrapf(xerr.NewErrCode(xerr.DatabaseDeletedError), "[DeleteServer] Delete Server Error")
	}
	return nodeStore.ClearServerCache(l.ctx, req.Id)
}

func deleteServerManagedStateTx(db *gorm.DB, serverID int64) error {
	if err := db.Session(&gorm.Session{SkipHooks: true}).Where("server_id = ?", serverID).Delete(&node.Node{}).Error; err != nil {
		return err
	}
	return db.Where("server_id = ?", serverID).Delete(&node.RelaySubscriptionGroup{}).Error
}
