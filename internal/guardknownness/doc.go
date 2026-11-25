// Package guardknownness holds a cross-package structural guard for the
// "degraded input" convention CLAUDE.md names: a field that gates autonomy or
// prioritization is paired with a <Field>Known bool, and the safe value is the
// ZERO value. For the fields listed in pairFields, this package checks that
// the companion is declared and that every if-condition in the declaring
// package that order-compares the field sits in a function that also
// references the companion. The check is lexical: returns, assignments and
// switch cases are not inspected, and fields not in pairFields are not
// covered. See pairing_test.go.
package guardknownness
