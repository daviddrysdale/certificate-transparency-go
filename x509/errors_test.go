package x509

import (
	"testing"
)

func TestTemplateIDs(t *testing.T) {
	for id, template := range idToError {
		if template.ID != id {
			t.Errorf("idToError[%v].id=%v; want %v", id, template.ID, id)
		}
	}
}

func TestErrorsAddIDFatal(t *testing.T) {
	var errs Errors
	errs.addIDFatal(ErrUnexpectedlyCriticalCertListExtension, "test extension")
	if err := errs.FirstFatal(); err == nil {
		t.Errorf("FirstFatal() = nil; want non-nil")
	}
}
