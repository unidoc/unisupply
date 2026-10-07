module example.com/floorsapp

go 1.21

require (
	example.com/rarelytagged v0.0.0
	example.com/stale v0.0.0
	gopkg.in/yaml.v3 v3.0.0
)

replace example.com/rarelytagged => ../rarelytagged

replace example.com/archivedgraphonly => ../archivedgraphonly

replace example.com/stale => ../stale

replace gopkg.in/yaml.v3 => ../yaml
