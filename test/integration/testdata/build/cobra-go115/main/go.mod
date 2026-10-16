module example.com/cobraapp

go 1.15

require (
	example.com/cobra v0.0.0
	example.com/testify v0.0.0
)

replace example.com/cobra => ../cobra

replace example.com/mousetrap => ../mousetrap

replace example.com/check => ../check

replace example.com/testify => ../testify
