module example.com/embedapp

go 1.21

require example.com/webkit v0.0.0

replace example.com/webkit => ../webkit

replace example.com/unusedlib => ../unusedlib
