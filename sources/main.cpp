#include "tools.h"
#include "window/mainwindow.h"
#include <QApplication>
#include <QMainWindow>

int main(int argc, char* argv[])
{
	Tools::init_log();

	QGuiApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
	QApplication app(argc, argv);

	MainWindow window;
	window.show();

	return app.exec();
}
