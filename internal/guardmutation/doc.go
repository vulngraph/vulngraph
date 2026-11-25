// Package guardmutation holds the mutation harness that audits this repo's
// structural guard tests.
//
// A structural guard is a test that makes a bug class unrepresentable rather
// than testing one behaviour: it reads the AST, walks the tree, or iterates a
// production registry and asserts a property of every element. A guard's
// existence is no evidence that it guards anything — a guard can pass with
// the exact bug it names fully present.
//
// This package closes that gap: for every guard it knows about, it applies the
// mutation that reintroduces the bug the guard exists to prevent, runs the
// guard, and requires it to FAIL. The driver is build-tagged `guardmutation`
// because it edits files in the working tree; the inventory check that keeps it
// honest (TestEveryDiscoveredGuardIsMutatedOrExempt) is NOT tagged and runs on
// every commit, so a new source-reading guard cannot be added without a
// decision being recorded here. Registry-iterating guards, and guards that read
// source only through another package, rely on the hand-maintained extraGuards
// list.
//
// There is no non-test code here on purpose: this file exists so the package
// has something to build when the tag is absent.
package guardmutation
