// Package schema validates the fixed request frame and each tool's arguments
// before anything else in the governor looks at them. Requirement G-4.
//
// The validator supports a deliberately small subset of JSON Schema:
//
//	type:                 object | string | integer | number | boolean | array
//	properties:           map of name -> schema (objects)
//	required:             list of property names (objects)
//	additionalProperties: false to reject unknown keys (objects); defaults to false
//	items:                schema for every element (arrays)
//	enum:                 list of allowed values (any scalar type)
//	minimum / maximum:    numeric bounds (integer, number)
//	minLength / maxLength: string length bounds
//	maxItems:             array length bound
//	pattern:              Go regexp the string must match
//
// That is enough to express every tool in the PoC and small enough to read in
// one sitting, which is the point: this code runs on hostile input, so it
// should be short. It uses only the standard library.
//
// What this package must never do:
//   - Pass unvalidated arguments to anything downstream.
//   - Default additionalProperties to true. Unknown keys are rejected unless
//     the schema explicitly allows them, so an agent cannot smuggle a field
//     the tool never declared.
package schema
