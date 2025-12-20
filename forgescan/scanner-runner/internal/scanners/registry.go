package scanners

type Scanner struct {
	Name  string
	Image string
}

var DefaultSAST = []Scanner{
	{Name: "bandit", Image: "forgescan/bandit:1.0"},
	{Name: "semgrep", Image: "forgescan/semgrep:1.0"},
}

var DefaultWeb = []Scanner{
	{Name: "owasp-zap", Image: "forgescan/zap:1.0"},
	{Name: "sqlmap", Image: "forgescan/sqlmap:1.0"},
}
