/*  monero-update - An downloaded/checker updater for Monero
 *
 *  Copyright (c) 2019, The Monero Project
 *
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without modification, are
 *  permitted provided that the following conditions are met:
 *  
 *  1. Redistributions of source code must retain the above copyright notice, this list of
 *     conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *  
 *  3. Neither the name of the copyright holder nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without specific
 *     prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 *  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
  function get_tristate_text(state)
  {
    if (state == TriState.TriTrue)
      return "<font color=\"green\">OK</font>";
    if (state == TriState.TriFalse)
      return "<font color=\"red\">Error</font>";
    return "waiting..."
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
      text: "state: " + updater.state
      Layout.leftMargin: 8
      Layout.rightMargin: 8
    }

    Text {
      text: "version: " + updater.version
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
        color: "#00ff00"
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
      clip: true
      Layout.leftMargin: 8
      Layout.rightMargin: 8
      Text {
        id: messages
        height: 16 * defaultText.height
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
