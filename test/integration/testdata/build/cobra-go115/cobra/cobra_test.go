// Only the dependency's own tests use check, as with gopkg.in/check.v1.
package cobra

import (
	"testing"

	_ "example.com/check"
)

func TestCobra(t *testing.T) {}
