module example.com/floorsapp

go 1.21

require (
	example.com/partlyused v0.0.0
	example.com/stale v0.0.0
)

replace example.com/partlyused => ../partlyused

replace example.com/archivedgraphonly => ../archivedgraphonly

replace example.com/stale => ../stale
