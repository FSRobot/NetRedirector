#pragma once

#include "property.h"
#include <QObject>
#include <QApplication>
#include <QGridLayout>
#include <QPushButton>
#include <QCloseEvent>
#include <QMessageBox>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QLineEdit>
#include <QHostAddress>
#include <QLabel>
#include "capture.h"

class MainWindow : public QWidget
{
	Q_OBJECT
public:
	MainWindow()
	{
		QMessageBox msg(QMessageBox::Icon::Warning, "警告", "运行此软件期间可能会导致被反作弊软件识别并封禁,谨慎使用!\r\n存在内核级流量代理与hook行为!", QMessageBox::StandardButton::Ok, this);
		msg.exec();

		init_window();
		capture = new Capture::Capture();
		capture->setState(Capture::Capture::State::Redirector);
		setWindowTitle("NetRedirector");
		setWindowIcon(QIcon::fromTheme(QIcon::ThemeIcon::NetworkWired));
	}
	~MainWindow() override
	{
		delete capture;
	}
protected:
	void closeEvent(QCloseEvent* event) override
	{
		tray->showMessage("Tips", "已退至后台运行~", QIcon::fromTheme(QIcon::ThemeIcon::NetworkWired));
	}
private:
	void CreateSystemTrayIcon()
	{
		exitAction = new QAction(QStringLiteral("退出"));
		connect(exitAction, &QAction::triggered, this, [&]()
			{
				capture->stop();
				std::this_thread::sleep_for(std::chrono::microseconds(100));
				uninstall();
				exit(EXIT_SUCCESS);
			});

		tray_menu = new QMenu(this);
		tray_menu->addAction(exitAction);
		tray = new QSystemTrayIcon(this);
		tray->setContextMenu(tray_menu);
		tray->setIcon(QIcon::fromTheme(QIcon::ThemeIcon::NetworkWired));
		tray->show();
		connect(tray, &QSystemTrayIcon::activated, this, [&](QSystemTrayIcon::ActivationReason reason)
			{
				if (reason == QSystemTrayIcon::DoubleClick) {
					if (isVisible()) hide();
					else show();
				}
			});
	}


	void init_window()
	{
		resize(250, 200);
		setWindowFlags(Qt::CoverWindow | Qt::MSWindowsFixedSizeDialogHint);
		CreateSystemTrayIcon();

		auto layout = new QGridLayout;
		setLayout(layout);

		auto label_server = new QLabel(this);
		label_server->setText("server: ");
		label_server->setAlignment(Qt::AlignRight);
		server_ip = new QLineEdit(this);
		server_ip->setText("::1");
		layout->addWidget(label_server, 0, 0);
		layout->addWidget(server_ip, 0, 1);

		auto label_80 = new QLabel(this);
		label_80->setText("80 port: ");
		label_80->setAlignment(Qt::AlignRight);
		server_p_80 = new QLineEdit(this);
		server_p_80->setText("680");
		layout->addWidget(label_80, 1, 0);
		layout->addWidget(server_p_80, 1, 1);

		auto label_443 = new QLabel(this);
		label_443->setText("443 port: ");
		label_443->setAlignment(Qt::AlignRight);
		server_p_443 = new QLineEdit(this);
		server_p_443->setText("6443");
		layout->addWidget(label_443, 2, 0);
		layout->addWidget(server_p_443, 2, 1);

		apply_btn = new QPushButton(this);
		apply_btn->setText(QStringLiteral("应用"));
		connect(apply_btn, &QPushButton::clicked, this, &MainWindow::apply_btn_click);
		layout->addWidget(apply_btn, 3, 1);

		start_btn = new QPushButton(this);
		start_btn->setText(QStringLiteral("启动"));
		connect(start_btn, &QPushButton::clicked, this, &MainWindow::start_btn_click);
		layout->addWidget(start_btn, 3, 0);

		auto author_label = new QLabel(this);
		author_label->setText("power by Baphomet & basil00");
		author_label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
		author_label->setAlignment(Qt::AlignHCenter);
		layout->addWidget(author_label, 4, 0, 1, 2);

	}

	void apply_btn_click()
	{
		std::string valid_msg;
		if (!isValidAddress(server_ip->text()))
		{
			valid_msg.append("非法IP地址!");
		}

		if (!isValidPort(server_p_80->text()))
		{
			if (!valid_msg.empty())valid_msg.append("\n");
			valid_msg.append("server_p_80非法端口!");
		}

		if (!isValidPort(server_p_443->text()))
		{
			if (!valid_msg.empty())valid_msg.append("\n");
			valid_msg.append("server_p_443非法端口!");
		}
		if (!valid_msg.empty()) {
			QMessageBox msg(QMessageBox::Icon::Warning, "Tips", valid_msg.c_str(), QMessageBox::StandardButton::Ok, this);
			msg.exec();
			return;
		}
		auto isAutoStart = static_cast<bool>(capture->isRunning());
		capture->stop();
		capture->clear();

		/*capture->add(Capture::RedirectInfo{ "66.66.66.66",80,server_ip->text().toStdString(), server_p_80->text().toUShort() });
		capture->add(Capture::RedirectInfo{ "66.66.66.66",443,server_ip->text().toStdString(),server_p_443->text().toUShort() });*/
		capture->add(
			Capture::RedirectInfo{
				"6666::6666",
				//"6.6.6.6",
				server_ip->text().toStdString(),
				{
				{80,{server_p_80->text().toUShort()}},
				{443,{server_p_443->text().toUShort()}}
				}
			}
		);
		if (isAutoStart) capture->start();
	}

	void start_btn_click() const
	{
		auto& isRunning = capture->isRunning();
		isRunning ? capture->stop() : capture->start();
		if (isRunning)
		{
			start_btn->setText(QStringLiteral("关闭"));
		}
		else
		{
			start_btn->setText(QStringLiteral("启动"));
		}
	}
private:
	static int uninstall()
	{
		SC_HANDLE manager = NULL, service = NULL;
		SERVICE_STATUS status;
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (manager == NULL)
		{
			SPDLOG_ERROR("error: failed to open service manager (%d)", GetLastError());
			return EXIT_FAILURE;
		}
		service = OpenService(manager, L"WinDivert", SERVICE_ALL_ACCESS);
		if (service == NULL)
		{
			SPDLOG_ERROR("error: failed to open WinDivert service (%d)", GetLastError());
			return EXIT_FAILURE;
		}
		if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
		{
			SPDLOG_ERROR("error: failed to stop WinDivert service (%d)", GetLastError());
			return EXIT_FAILURE;
		}
		if (status.dwCurrentState != SERVICE_STOPPED)
		{
			SPDLOG_ERROR("error: failed to stop WinDivert service");
			return EXIT_FAILURE;
		}
		CloseServiceHandle(service);
		CloseServiceHandle(manager);

		SPDLOG_INFO("uninstall success");
		return EXIT_SUCCESS;
	}

	static bool isValidAddress(const QString& ip)
	{
		QHostAddress addr;
		return addr.setAddress(ip);
	}
	static bool isValidPort(const QString& portStr)
	{
		bool ok = false;
		int port = portStr.toInt(&ok);
		return ok && port >= 0 && port <= 65535;
	}

	QSystemTrayIcon* tray;
	QMenu* tray_menu;
	QAction* exitAction;
	QPushButton* start_btn, * apply_btn;
	QLineEdit* server_ip, * server_p_80, * server_p_443;
	Capture::Capture* capture{ nullptr };
};