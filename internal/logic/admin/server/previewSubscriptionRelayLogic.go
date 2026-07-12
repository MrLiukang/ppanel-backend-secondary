package server

import (
	"context"

	"github.com/perfect-panel/server/internal/svc"
	"github.com/perfect-panel/server/internal/types"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/xerr"
	"github.com/pkg/errors"
)

type PreviewSubscriptionRelayLogic struct {
	logger.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewPreviewSubscriptionRelayLogic(ctx context.Context, svcCtx *svc.ServiceContext) *PreviewSubscriptionRelayLogic {
	return &PreviewSubscriptionRelayLogic{
		Logger: logger.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *PreviewSubscriptionRelayLogic) PreviewSubscriptionRelay(req *types.SubscriptionRelayPreviewRequest) (*types.SubscriptionRelayPreviewResponse, error) {
	resp, err := FetchSubscriptionRelayPreview(l.ctx, req.URL, SubscriptionRelayImportOptions{
		ListenPortStart: req.ListenPortStart,
		ListenPortStep:  req.ListenPortStep,
	})
	if err != nil {
		l.Errorf("[PreviewSubscriptionRelay] error: %v", err)
		return nil, errors.Wrapf(xerr.NewErrMsg(err.Error()), "PreviewSubscriptionRelay error: %v", err.Error())
	}
	return resp, nil
}
