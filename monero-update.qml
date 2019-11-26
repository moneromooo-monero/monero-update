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

import QtQuick 2.9
import QtQuick.Window 2.1
import QtQuick.Controls 1.2
import QtQuick.Controls.Styles 1.4
import QtQuick.Layouts 1.1
import QtGraphicalEffects 1.0
import TriState 1.0

ApplicationWindow {
  id: root
  visible: true
  width: header.implicitWidth * 1.2

  property double scale: 1.15

  function bytes_str(bytes, add_unit) {
    var unit_string = add_unit == null ? "" : add_unit < 1024 ? " bytes" : add_unit < 1024 * 1024 ? " kB" : add_unit < 1024 * 1024 * 1024 ? " MB" : " GB"
    var scale = add_unit == null ? 1 : add_unit < 1024 ? 1 : add_unit < 1024 * 1024 ? 1024 : add_unit < 1024 * 1024 * 1024 ? 1024 * 1024 : 1024 * 1024 * 1024
    return qsTr("%1%2").arg((bytes / scale).toFixed(1)).arg(unit_string)
  }
  function get_tristate_text(state, text)
  {
    if (state == TriState.TriTrue)
      return "<font color=\"green\">" + (text === undefined ? "OK" : text) + "</font>";
    if (state == TriState.TriFalse)
      return "<font color=\"red\">" + (text === undefined ? "Error" : text) + "</font>";
    return text === undefined ? "waiting..." : text
  }

  // size helpers
  Text {
    visible: false
    id: baseText
  }
  Text {
    visible: false
    id: defaultText
    font.pixelSize: baseText.font.pixelSize * root.scale
  }
  FontLoader {
    id: fontAwesome
    source: "qrc:/content/fontawesome.otf"
  }


  // UI
  ColumnLayout {
    id: main
    anchors.fill: parent

    RowLayout {
      Layout.fillWidth: true
      Layout.leftMargin: 8
      Layout.rightMargin: 8
      ColumnLayout {
        Text {
          id: header
          Layout.leftMargin: defaultText.height * 2
          font.pixelSize: defaultText.font.pixelSize * 1.4
          text: "<font size=+2><b>monero-update</b></font> - A secure updater/installer for <img src=\"qrc:///content/monero48.png\" height=" + font.pixelSize + ">onero"
          textFormat: Text.RichText
          topPadding: defaultText.font.pixelSize / 2
          bottomPadding: defaultText.font.pixelSize / 2
        }
      }
    }

    Text {
      text: "State: " + get_tristate_text(updater.stateOutcome, updater.state)
      textFormat: Text.RichText
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    Text {
      text: "Version: " + get_tristate_text(updater.version === "" ? TriState.TriUnknown : TriState.TriTrue, updater.version)
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    Text {
      text: "DNS valid: " + get_tristate_text(updater.dnsValid)
      textFormat: Text.RichText
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    RowLayout {
      id: gitianProgress
      visible: updater.processedGitianSigs < updater.totalGitianSigs
      Layout.leftMargin: 8
      Layout.rightMargin: 8
      ProgressBar {
        id: gitianProgressBar
        minimumValue: 0
        maximumValue: updater.totalGitianSigs
        value: updater.processedGitianSigs
      }
      Text {
        text: "Processed " + updater.processedGitianSigs + "/" + updater.totalGitianSigs + " signatures"
      }
    }

    Text {
      property string num_color: { var sigs = updater.validGitianSigs; if (sigs >= updater.minValidGitianSigs) return "green"; if (sigs >= updater.minValidGitianSigs / 2) return "yellow"; if (sigs > 0) return "orange"; return "red"; }
      text: "Gitian matches: " + (updater.minValidGitianSigs == 0 ? "waiting..." : ("<font color=\"" + num_color + "\">" + updater.validGitianSigs + "/" + updater.minValidGitianSigs + "</font>"))
      textFormat: Text.RichText
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    RowLayout {
      id: downloadProgress
      visible: false
      Layout.leftMargin: 8
      Layout.rightMargin: 8
      ProgressBar {
        id: downloadProgressBar
        minimumValue: 0
      }
      Text {
        id: downloadProgressText
      }
      Button {
        id: retry
        text: "Retry"
        onClicked: updater.retryDownload()
      }
    }

    Text {
      text: "Hash valid: " + get_tristate_text(updater.hashValid)
      textFormat: Text.RichText
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    RowLayout {
      id: success
      visible: false
      Layout.leftMargin: 8
      Layout.rightMargin: 8
      Text {
        color: "green"
        font.pointSize: defaultText.font.pointSize * 1.3
        text: "Verified and ready to install:"
      }
      Text {
        id: successFilename
        property string filename: ""
        font.pointSize: defaultText.font.pointSize * 1.1
        text: "<a href=\"file:// + filename + \">" + filename + "</a>"
        textFormat: Text.RichText
        onLinkActivated: Qt.openUrlExternally("file://" + filename)
      }
    }

    CheckBox {
      id: showDetails
      checked: false
      text: "Show details"
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    ScrollView {
      visible: showDetails.checked
      Layout.fillWidth: true
      Layout.fillHeight: true
      clip: true
      Layout.leftMargin: 8
      Layout.rightMargin: 8
      TextEdit {
        id: messages
        readOnly: true
        selectByMouse: true
      }
    }

    Item {
      Layout.bottomMargin: 2
    }
  }

  Connections {
    target: updater
    onMessage: function(msg) { messages.text += msg + '\n' }
    onDownloadStarted: {
      downloadProgress.visible = true
      downloadProgressText.text = "starting..."
      retry.visible = false
    }
    onDownloadFinished: function(success) {
      if (success)
        downloadProgress.visible = false
      else
        downloadProgressText.text = "Failed"
      retry.visible = !success
    }
    onDownloadProgress: function(downloaded, total) {
      downloadProgressBar.indeterminate = total == 0
      downloadProgressBar.maximumValue = total
      downloadProgressBar.value = downloaded
      if (total == 0)
        downloadProgressText.text = bytes_str(downloaded, 0) + " bytes"
      else
        downloadProgressText.text = bytes_str(downloaded, total)  + "/" + bytes_str(total, total)
    }
    onValidUpdateReady: function(filename) {
      successFilename.filename = filename
      success.visible = true
    }
  }
}
