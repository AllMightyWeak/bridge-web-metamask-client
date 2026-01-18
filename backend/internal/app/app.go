package app

type App struct {
	HTTP Runner
}

type Runner interface {
	Run() error
}

func New(http Runner) *App {
	return &App{HTTP: http}
}

func (a *App) Run() error {
	return a.HTTP.Run()
}
