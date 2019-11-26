/*  monero-update - An downloaded/checker updater for Monero
 *
 *  Copyright (c) 2019, The Monero Project
 *
 *  All rights reserved.
 *  
 *  monero-update is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  monero-update is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with monero-update.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include "misc_log_ex.h"
#include "string_tools.h"
#include "updater.h"

Q_DECLARE_METATYPE(uint32_t)
Q_DECLARE_METATYPE(std::string)

int main(int argc, char **argv)
{
  QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
  QCoreApplication::setOrganizationName("None");

  QQuickWindow::setDefaultAlphaBuffer(true);

  QGuiApplication gui(argc, argv);
  qRegisterMetaType<uint32_t>("uint32_t");
  qRegisterMetaType<TriState::tristate_t>("tristate_t");
  qRegisterMetaType<std::string>("std::string");
  qmlRegisterType<Updater>("Updater", 1, 0, "Updater");
  qmlRegisterUncreatableMetaObject(TriState::staticMetaObject, "TriState", 1, 0, "TriState", "TriState is uncreatable");

  if (getenv("MONERO_LOGS"))
  {
    epee::string_tools::set_module_name_and_folder(argv[0]);
    mlog_configure(mlog_get_default_log_path("monero-update.log"), false);
  }

  Updater updater(&gui);

  QQmlApplicationEngine engine;
  engine.rootContext()->setContextProperty("mainApp", &gui);
  engine.rootContext()->setContextProperty("updater", &updater);

  engine.load(QStringLiteral("qrc:///monero-update.qml"));
  return gui.exec();
}
