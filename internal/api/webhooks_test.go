package api_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/notify"
)

func TestTheWebhookEventEnumIsTheNotifyVocabulary(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(contract.CreateWebhookRequest{}), reflect.TypeOf(contract.UpdateWebhookRequest{})} {
		field, ok := typ.FieldByName("EventTypes")
		require.True(t, ok)
		require.Equal(t, notify.EventTypesEnum, field.Tag.Get("enum"), typ.Name())
	}
}
