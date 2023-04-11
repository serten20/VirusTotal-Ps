
#APIKEY
$VTApiKey = ""




if ($VTApiKey.Length -eq 0){
Write-Warning "[!] Enter your Apikey in VirusTotal.ps1 file"
pause
exit			
}

Else {

}

$RutaIP = "\data\IP-output.json"
$RutaHash = "\data\Hash-Output.json"
$RutaURL ="\data\URL-Output.json"
$RutaDomain ="\data\Domain-Output.json"


$resources = Get-Content -Path .\resources.txt


if ($resources.count -eq 0){
					Write-Warning "[!] resources.txt file is empty "
					pause
                    exit	
				}

Else {

}









Remove-Item -ErrorAction SilentlyContinue -Path Data -Recurse
mkdir Data 


Function showmenu {
	
    Clear-Host
	
	 Write-host ""
Write-Host @"
     ___ ___  __                      _______         __           __
    |   |   ||__|.----..--.--..-----.|_     _|.-----.|  |_ .---.-.|  |
    |   |   ||  ||   _||  |  ||__ --|  |   |  |  _  ||   _||  _  ||  |
     \_____/ |__||__|  |_____||_____|  |___|  |_____||____||___._||__|

"@ -ForegroundColor Blue 

 Write-Host ""
 Write-Host ""	
	
    
    Write-Host " [1] Check Hashes"
    Write-Host " [2] Check IP's"
    Write-Host " [3] Check URL's"
	Write-Host " [4] Check Domains"
    Write-Host " [5] Exit"
	Write-Host ""	
}
 
showmenu


 
while(($inp = Read-Host -Prompt "Please select an option: ") -ne "5"){
 
switch($inp){
        1 {
			Clear-Host
			$incre = 0
			 Write-Host ""
 Write-Host "---------------------------------------------------------------------------------------------"
 Write-Host "----------------------------- CHECKING HASH IN VIRUSTOTAL -----------------------------------"
 Write-Host "---------------------------------------------------------------------------------------------"
 Write-Host ""
 
 #calcular tiempo estimado en segundos
 $tiempoEstimadoSegundos = $resources.Count*17
 
 #mostrar tiempo estimado en formato hh\mm\ss
 $s = $tiempoEstimadoSegundos
 $tiempoEstimadoFormato =  [timespan]::fromseconds($s)

 

 
 
if ($resources.count -ge 4) {
	 
		Write-Warning "[!] Due to the limitation of the free API (4 queries per minute) this script performs a delay of 17 seconds in each analysis." 
		Write-Host "" 
		
		Write-Host "[>] Estimated time:   " -NoNewLine
		Write-Host -ForegroundColor Yellow -NoNewLine  $tiempoEstimadoFormato
		Write-Host " (hh:mm:ss)" -NoNewLine
		Write-Host ""
	 
	}
else {
		Write-Host "[>] Estimated time:  " -NoNewLine 
		Write-Host -ForegroundColor Yellow -NoNewLine $resources.Count 
		Write-Host -NoNewLine " seconds" 
		Write-Host ""
		
	}


 Write-Host "[>] Total to be analyzed: " -NoNewLine
 Write-Host -ForegroundColor Red -NoNewLine $resources.Count  
 Write-Host -NoNewLine " samples"  
 Write-Host ""
 Write-Host ""
 
 

 
	$myvar = @()
        foreach ($hash in $resources)
            {
                ## verifica si hay mas de cuatro hashes y añade un sleeptime ya que la api gratuita limita a 4 consultas por minuto(4/min) 
                    if ($resources.count -ge 4) {
						## Subir el hash!
                    $VTbody = @{resource = $hash; apikey = $VTApiKey}
                    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

					$myvar += $VTresult

					$incre = 1+$incre++

					$MuestrasRestantes = (($resources.Count)-($incre))+1
				
				
				$tiempo_restantes_segundos = $MuestrasRestantes*17
				$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
				$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
				
				if ($VTresult.response_code -eq "0") {
					$Vendorstotal ="N/D"
					$peligroso ="N/D"
					$Fcolor = "Darkgray"
				}
				else{
					$Vendorstotal = $VTresult.total
					$peligroso =$VTresult.positives
				}
				
				If ($VTresult.positives -ge "1"){
					$Fcolor = "red"
				}
				If ($VTresult.positives -eq "0"){
					$Fcolor = "Green"
				}
				
				if ($hash.Length -eq 32){
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Cyan -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "md5" -ForegroundColor Cyan -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow

					
				}

				elseif ($hash.Length -eq 40) {
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Magenta -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "Sha1" -ForegroundColor Magenta -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow
					
				}

				elseif ($hash.Length -eq 64) {
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Green -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "Sha2" -ForegroundColor Green -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow
					
				
				}

				else {
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Blue -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "Other" -ForegroundColor Blue -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow
					
					
				}
					
                    Start-Sleep -seconds 17
						
						
					}
					
					
                    else {

                    $VTbody = @{resource = $hash; apikey = $VTApiKey}
                    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody 

					$myvar += $VTresult

				$incre = 1+$incre++

				$MuestrasRestantes = (($resources.Count)-($incre))+1

				
				$tiempo_restantes_segundos = $MuestrasRestantes*1
				$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
				$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
				
				
				if ($VTresult.response_code -eq "0") {
					$Vendorstotal ="N/D"
					$peligroso ="N/D"
					$Fcolor = "Darkgray"
				}
				else{
					$Vendorstotal = $VTresult.total
					$peligroso =$VTresult.positives
				}
				
				If ($VTresult.positives -ge "1"){
					$Fcolor = "red"
				}
				If ($VTresult.positives -eq "0"){
					$Fcolor = "Green"
				}
				
				
				
				if ($hash.Length -eq 32){
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Cyan -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "md5" -ForegroundColor Cyan -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow

					
				}

				elseif ($hash.Length -eq 40) {
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Magenta -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "Sha1" -ForegroundColor Magenta -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow
					
				}

				elseif ($hash.Length -eq 64) {
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Green -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "Sha2" -ForegroundColor Green -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow
					
				
				}

				else {
					Write-Host "   [$incre]" -NoNewLine
					Write-Host " $hash" -ForegroundColor Blue -NoNewLine
					Write-Host " Hash:" -NoNewLine
					Write-Host "Other" -ForegroundColor Blue -NoNewLine
					Write-Host " Vendors:" -NoNewLine
					Write-Host "$Vendorstotal" -ForegroundColor Yellow -NoNewLine
					Write-Host " Mark as Dangerous:" -NoNewLine
					Write-Host "$peligroso " -ForegroundColor $Fcolor -NoNewLine
					Write-Host "($tiemporestanteFormato)" -ForegroundColor Yellow
					
					
				}
					
					
					
                    Start-Sleep -seconds 1
						
					
					}
            
             
            }
			
		
			$CustomRutaHash = "." + $RutaHash
			$myvar | ConvertTo-Json -Depth 10 | Out-File -FilePath $CustomRutaHash      
			$ruta = $PWD
		
			$ficheroExcel = "$ruta\VT-hash-Report.xlsx"
			$CustomRuta = "$ruta" + "$RutaHash"
			$json = Get-Content -Raw $CustomRuta | ConvertFrom-Json
		
			$Excel = New-Object -com Excel.Application
			$Excel.Visible = $false
			$Excel.DisplayAlerts = $false
			
			$Book = $Excel.Workbooks.add()
			$WorkSheet = $Book.Sheets.Item(1)
			$WorkSheet.Name = "VT-HASH"
				
			ForEach($ws in $WorkSheet)

			{

				$ws.Range($ws.Rows(1),$ws.Rows($ws.Rows.Count)).Delete() | Out-null

			}


			$tableRange = $worksheet.Range("A1:J2")
			$table = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,$tableRange,$null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes,$null)

			$table.ListColumns.Item(1).Name = "VirusTotal_Exist"
			$table.ListColumns.Item(2).Name = "resource"
			$table.ListColumns.Item(3).Name = "total vendors"
			$table.ListColumns.Item(4).Name = "positives"
			$table.ListColumns.Item(5).Name = "scan_date"
			$table.ListColumns.Item(6).Name = "permalink"
			$table.ListColumns.Item(7).Name = "md5"
			$table.ListColumns.Item(8).Name = "sha1"
			$table.ListColumns.Item(9).Name = "sha256"
			$table.ListColumns.Item(10).Name = "verbose_msg"
			
			$table.ListColumns.Item(10).DataBodyRange.NumberFormat = "$#,##0.00"
			
			$VirusTotalExistS = $json.response_code
			$ResourcesS = $json.resource
			$totalS = $json.total
			$positiveS = $json.positives
			$ScanDateS = $json.scan_date
			$linkS = $json.permalink
			$md5S = $json.md5
			$sha1S = $json.sha1
			$sha256S = $json.sha256
			$verbosemsgS = $json.verbose_msg
			
			$scansS = $json.scans
			
			$totalv=$scansS.count
			
			
			
			foreach ($VirusTotalExist in $VirusTotalExistS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,1) = "$VirusTotalExist"
						if ($positive -ge 1){
							$table.DataBodyRange.Item($row,1).Interior.ColorIndex = 3
							$table.DataBodyRange.Item($row, 1).HorizontalAlignment = -4108
							}
						Else {
							$table.DataBodyRange.Item($row, 1).HorizontalAlignment = -4108
						}
						
						
					}
			$row = 0
			foreach ($Resources in $ResourcesS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,2) = "$Resources"
						
					}
					
			$row = 0		
			foreach ($total in $totalS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,3) = "$total"		
						if ($total -ge 1){
							$table.DataBodyRange.Item($row,3).Interior.ColorIndex = 15
							$table.DataBodyRange.Item($row, 3).HorizontalAlignment = -4108
							}
						
					}
					
					
			$row = 0		
			foreach ($positive in $positiveS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,4) = "$positive"		
						if ($positive -ge 1){
							$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 3
							$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
							}
						Elseif ($positive -eq 0){
							$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
						}
						Else {
							$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
						}
					}
			
			$row = 0		
			foreach ($ScanDate in $ScanDateS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,5) = "$ScanDate"		
					}
			
			$row = 0		
			foreach ($link in $linkS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,6) = "$link"		
					}
					
			$row = 0		
			foreach ($md5 in $md5S)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,7) = "$md5"		
					}
					
			$row = 0		
			foreach ($sha1 in $sha1S)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,8) = "$sha1"		
					}
			
			$row = 0		
			foreach ($sha256 in $sha256S)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,9) = "$sha256"		
					}
					
			$row = 0		
			foreach ($verbosemsg in $verbosemsgS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,10) = "$verbosemsg"		
					}
			
			
			$Book.SaveAs($ficheroExcel) 	
			$Book.Close()
			$Excel.Quit()
			
			
			Write-host ""
			Write-Host " The xlsx file is being generated, wait a few seconds. (" -nonewline 
			write-host "$ficheroExcel" -nonewline -ForegroundColor Green
			write-host ")"
			
			Start-Sleep -seconds 5
			
            
            pause; 
            break
        }
        2 {
            Clear-Host
			$incre = 0
             
 Write-Host ""
 Write-Host "---------------------------------------------------------------------------------------------"
 Write-Host "----------------------------- CHECKING IP IN VIRUSTOTAL -------------------------------------"
 Write-Host "---------------------------------------------------------------------------------------------"
 Write-Host ""
 
 #calcular tiempo estimado en segundos
 $tiempoEstimadoSegundos = $resources.Count*17
 
 #mostrar tiempo estimado en formato hh\mm\ss
 $s = $tiempoEstimadoSegundos
 $tiempoEstimadoFormato =  [timespan]::fromseconds($s)

 

 
 
if ($resources.count -ge 4) {
	 
		Write-Warning "[!] Due to the limitation of the free API (4 queries per Minute) this script performs a delay of 17 seconds in each analysis." 
		Write-Host "" 
		
		Write-Host "[>] Estimated time:   " -NoNewLine
		Write-Host -ForegroundColor Yellow -NoNewLine  $tiempoEstimadoFormato
		Write-Host " (hh:mm:ss)" -NoNewLine
		Write-Host ""
	 
	}
else {
		Write-Host "[>] Estimated time:  " -NoNewLine 
		Write-Host -ForegroundColor Yellow -NoNewLine $resources.Count 
		Write-Host -NoNewLine " seconds" 
		Write-Host ""
		
	}


 Write-Host "[>] Total to be analyzed: " -NoNewLine
 Write-Host -ForegroundColor Red -NoNewLine $resources.Count  
 Write-Host -NoNewLine " IP's"  
 Write-Host ""
 Write-Host ""
 
 

	$myvar = @()
        foreach ($hash in $resources)
            {
					## verifica si hay mas de cuatro hashes y añade un sleeptime ya que la api gratuita limita a 4 consultas por minuto(4/min) 
							if ($resources.count -ge 4) {	
							
							$urlVT="https://www.virustotal.com/api/v3/ip_addresses/$hash"
							$headers = @{"x-apikey" = $VTApiKey}

							$VTresult=Invoke-RestMethod -Method GET -Uri $urlVT -Headers $headers
							
							$myvar += $VTresult
							
							$incre = 1+$incre++
						
							$MuestrasRestantes = (($resources.Count)-($incre))+1
						
							$tiempo_restantes_segundos = $MuestrasRestantes*17
							$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
							$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
						
									
							$inofensivo = $VTresult.data.attributes.last_analysis_stats.harmless
							$malicioso = $VTresult.data.attributes.last_analysis_stats.malicious
							$sospechoso = $VTresult.data.attributes.last_analysis_stats.suspicious
							$indetectado = $VTresult.data.attributes.last_analysis_stats.undetected
							
							$totalvendors= $inofensivo + $malicioso + $sospechoso + $indetectado
							
							
							If ($inofensivo -ge "1"){
								$Fcolorinofensivo = "green"
							}
							else{
								$Fcolorinofensivo = "DarkGray"
							}							
							
							If ($malicioso -ge "1"){
								$Fcolormalicioso = "red"
							}
							else{
								$Fcolormalicioso = "Green"
							}
							
							If ($sospechoso -eq "0"){
								$Fcolorsospechoso = "Green"
							}
							else{
								$Fcolorsospechoso = "6"
							}
							
							If ($indetectado -ge "0"){
								$Fcolorndetectado = "DarkGray"
							}
							
							
							Write-Host "   [$incre]" -NoNewLine
							Write-Host " IP:" -NoNewLine
							Write-Host " $hash" -ForegroundColor Yellow -NoNewLine
							Write-Host " Vendors:" -NoNewLine
							Write-Host "$totalvendors" -ForegroundColor Yellow -NoNewLine
							Write-Host " [Malicious:" -NoNewLine
							Write-Host "$malicioso" -ForegroundColor $Fcolormalicioso -NoNewLine
							Write-Host " Suspicious:" -NoNewLine
							Write-Host "$sospechoso" -ForegroundColor $Fcolorsospechoso -NoNewLine
							Write-Host " Harmless:" -NoNewLine
							Write-Host "$inofensivo" -ForegroundColor $Fcolorinofensivo -NoNewLine
							Write-Host " Undetected:" -NoNewLine
							Write-Host "$indetectado" -ForegroundColor $Fcolorndetectado -NoNewLine
							Write-Host "]" -NoNewLine
							Write-Host " ($tiemporestanteFormato)" -ForegroundColor Yellow
							
							
							Start-Sleep -seconds 17
						
					}
                    else {
					
						
							$urlVT="https://www.virustotal.com/api/v3/ip_addresses/$hash"
							$headers = @{"x-apikey" = $VTApiKey}

							$VTresult=Invoke-RestMethod -Method GET -Uri $urlVT -Headers $headers
							
							$myvar += $VTresult
							
							$incre = 1+$incre++
						
							$MuestrasRestantes = (($resources.Count)-($incre))+1
						
							$tiempo_restantes_segundos = $MuestrasRestantes*1
							$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
							$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
						
									
							$inofensivo = $VTresult.data.attributes.last_analysis_stats.harmless
							$malicioso = $VTresult.data.attributes.last_analysis_stats.malicious
							$sospechoso = $VTresult.data.attributes.last_analysis_stats.suspicious
							$indetectado = $VTresult.data.attributes.last_analysis_stats.undetected
							
							$totalvendors= $inofensivo + $malicioso + $sospechoso + $indetectado
							
							
							If ($inofensivo -ge "1"){
								$Fcolorinofensivo = "green"
							}
							else{
								$Fcolorinofensivo = "DarkGray"
							}							
							
							If ($malicioso -ge "1"){
								$Fcolormalicioso = "red"
							}
							else{
								$Fcolormalicioso = "Green"
							}
							
							If ($sospechoso -eq "0"){
								$Fcolorsospechoso = "Green"
							}
							else{
								$Fcolorsospechoso = "6"
							}
							
							If ($indetectado -ge "0"){
								$Fcolorndetectado = "DarkGray"
							}
							
							
							Write-Host "   [$incre]" -NoNewLine
							Write-Host " IP:" -NoNewLine
							Write-Host " $hash" -ForegroundColor Yellow -NoNewLine
							Write-Host " Vendors:" -NoNewLine
							Write-Host "$totalvendors" -ForegroundColor Yellow -NoNewLine
							Write-Host " [Malicious:" -NoNewLine
							Write-Host "$malicioso" -ForegroundColor $Fcolormalicioso -NoNewLine
							Write-Host " Suspicious:" -NoNewLine
							Write-Host "$sospechoso" -ForegroundColor $Fcolorsospechoso -NoNewLine
							Write-Host " Harmless:" -NoNewLine
							Write-Host "$inofensivo" -ForegroundColor $Fcolorinofensivo -NoNewLine
							Write-Host " Undetected:" -NoNewLine
							Write-Host "$indetectado" -ForegroundColor $Fcolorndetectado -NoNewLine
							Write-Host "]" -NoNewLine
							Write-Host " ($tiemporestanteFormato)" -ForegroundColor Yellow
							
							
							Start-Sleep -seconds 1
					
						
					}
                
               
             
            }

		
		$export = $myvar
	
		
		$CustomRutaIP = "." + $RutaIP
		$export | ConvertTo-Json -Depth 10 | Out-File -FilePath $CustomRutaIP
		$ruta = $PWD
	
		$ficheroExcel = "$ruta\VT-IP-Report.xlsx"
		$CustomRuta = "$ruta" + "$RutaIP"
		$json = Get-Content -Raw $CustomRuta | ConvertFrom-Json
	
		$Excel = New-Object -com Excel.Application
		$Excel.Visible = $false
		$Excel.DisplayAlerts = $false
		
		$Book = $Excel.Workbooks.add()
		$WorkSheet = $Book.Sheets.Item(1)
		$WorkSheet.Name = "VT-IP"


		ForEach($ws in $WorkSheet)

		{

			$ws.Range($ws.Rows(1),$ws.Rows($ws.Rows.Count)).Delete() | Out-null

		}


		$tableRange = $worksheet.Range("A1:J2")
		$table = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,$tableRange,$null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes,$null)

		$table.ListColumns.Item(1).Name = "Scan Resource"
		$table.ListColumns.Item(2).Name = "harmless"
		$table.ListColumns.Item(3).Name = "malicious"
		$table.ListColumns.Item(4).Name = "suspicious"
		$table.ListColumns.Item(5).Name = "undetected"
		$table.ListColumns.Item(6).Name = "as_owner"
		$table.ListColumns.Item(7).Name = "continent"
		$table.ListColumns.Item(8).Name = "country"
		$table.ListColumns.Item(9).Name = "last_analysis_date"
		$table.ListColumns.Item(10).Name = "link"

		$table.ListColumns.Item(10).DataBodyRange.NumberFormat = "$#,##0.00"


		$ScanResourceS = $json.data.id
		$harmlessS = $json.data.attributes.last_analysis_stats.harmless
		$maliciousS = $json.data.attributes.last_analysis_stats.malicious
		$suspiciousS = $json.data.attributes.last_analysis_stats.suspicious
		$undetectedS = $json.data.attributes.last_analysis_stats.undetected
		$AsOwnerS = $json.data.attributes.as_owner
		$continentS = $json.data.attributes.continent
		$countryS = $json.data.attributes.country
		$last_analysis_dateS = $json.data.attributes.last_analysis_date
		$linkS = $json.data.id
		
		$row = 0
		foreach ($ScanResource in $ScanResourceS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,1) = "$ScanResource"
					
					
				}
		$row = 0
		foreach ($harmless in $harmlessS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,2) = "$harmless"
					
				}
				
		$row = 0		
		foreach ($malicious in $maliciousS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,3) = "$malicious"		
					if ($malicious -ge 1){
						$table.DataBodyRange.Item($row,3).Interior.ColorIndex = 3
						$table.DataBodyRange.Item($row, 3).HorizontalAlignment = -4108
						}
					Else {
						$table.DataBodyRange.Item($row,3).Interior.ColorIndex = 4
						$table.DataBodyRange.Item($row, 3).HorizontalAlignment = -4108
					}
				}
				
		$row = 0		
		foreach ($suspicious in $suspiciousS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,4) = "$suspicious"
					if ($suspicious -ge 1){
						$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 46
						$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
						}
					Elseif ($suspicious -eq 0){
							$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
						}
					Else {
						$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 4
						$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
					}
				}
				
		$row = 0		
		foreach ($undetected in $undetectedS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,5) = "$undetected"
					if ($undetected -ge 1){
						$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 15
						$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
						}
						
					Elseif ($undetected -eq 0){
							$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
						}
					Else {
						$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 4
						$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
					}
				}
				
		$row = 0		
		foreach ($AsOwner in $AsOwnerS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,6) = "$AsOwner"
					
				}
				
		$row = 0		
		foreach ($continent in $continentS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,7) = "$continent"
					
				}
				
		$row = 0		
		foreach ($country in $countryS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,8) = "$country"
					
				}
				
		$row = 0		
		foreach ($last_analysis_date in $last_analysis_dateS)
				{
					
					$row++ | Out-null
					$FormatoLastAnalysis =[DateTimeOffset]::FromUnixTimeSeconds($last_analysis_date).ToString('yyyy-MM-dd')
					$table.DataBodyRange.Item($row,9) = "$FormatoLastAnalysis"
					
				}

		
		$row = 0		
		foreach ($link in $linkS)
				{
					$row++ | Out-null
					$table.DataBodyRange.Item($row,10) = "https://www.virustotal.com/gui/ip-address/$link"
					
					
				}
				
			$Book.SaveAs($ficheroExcel) 
			
			$Book.Close()
			$Excel.Quit()
			
			
			

			Write-host ""
			Write-Host " The xlsx file is being generated, wait a few seconds. (" -nonewline 
			write-host "$ficheroExcel" -nonewline -ForegroundColor Green
			write-host ")"
			
			Start-Sleep -seconds 5
		
		

	

			
            pause; 
            break
        }
        3 {
            Clear-Host
			$incre = 0
			
			            
		 Write-Host ""
		 Write-Host "---------------------------------------------------------------------------------------------"
		 Write-Host "----------------------------- CHECKING URL IN VIRUSTOTAL ------------------------------------"
		 Write-Host "---------------------------------------------------------------------------------------------"
		 Write-Host ""
		 
		 #calcular tiempo estimado en segundos
		 $tiempoEstimadoSegundos = $resources.Count*17
		 
		 #mostrar tiempo estimado en formato hh\mm\ss
		 $s = $tiempoEstimadoSegundos
		 $tiempoEstimadoFormato =  [timespan]::fromseconds($s)

		 

		 
		 
		if ($resources.count -ge 4) {
			 
				Write-Warning "[!] Due to the limitation of the free API (4 queries per Minute) this script performs a delay of 17 seconds in each analysis." 
				Write-Host "" 
				
				Write-Host "[>] Estimated time:   " -NoNewLine
				Write-Host -ForegroundColor Yellow -NoNewLine  $tiempoEstimadoFormato
				Write-Host " (hh:mm:ss)" -NoNewLine
				Write-Host ""
			 
			}
		else {
				Write-Host "[>] Estimated time:  " -NoNewLine 
				Write-Host -ForegroundColor Yellow -NoNewLine $resources.Count 
				Write-Host -NoNewLine " seconds" 
				Write-Host ""
				
			}





        Write-Host "[>] Total to be analyzed: " -NoNewLine
        Write-Host -ForegroundColor Red -NoNewLine $resources.Count  
        Write-Host -NoNewLine " URL's"  
        Write-Host ""
        Write-Host ""
		 
 

		$myvar = @()
			foreach ($hash in $resources)
				 {
						
						if ($resources.count -ge 4) {
							
						
						$VTbody = @{resource = $hash; apikey = $VTApiKey; scan=1}
						$VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/url/report' -Body $VTbody
							
						$myvar += $VTresult
					
						$incre = 1+$incre++
					
						$MuestrasRestantes = (($resources.Count)-($incre))+1
					
						$tiempo_restantes_segundos = $MuestrasRestantes*17
						$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
						$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
					
						
						$totalvendors = $VTresult.total
						$malicioso = $VTresult.positives
                        $Url = $VTresult.url

                        
						If ($malicioso -ge "1"){
								$Fcolormalicioso = "red"
						}
						else{
								$Fcolormalicioso = "Green"
						}

						Write-Host "   [$incre]" -NoNewLine
						Write-Host " URL:" -NoNewLine
						Write-Host " $hash" -ForegroundColor Yellow -NoNewLine
						Write-Host " Vendors:" -NoNewLine
						Write-Host "$totalvendors" -ForegroundColor Yellow -NoNewLine
						Write-Host " [Malicious:" -NoNewLine
						Write-Host "$malicioso" -ForegroundColor $Fcolormalicioso -NoNewLine
						Write-Host " URL:" -NoNewLine
						Write-Host "$url" -ForegroundColor Darkgray -NoNewLine
						Write-Host "]" -NoNewLine
						Write-Host " ($tiemporestanteFormato)" -ForegroundColor Yellow 
						
						
						Start-Sleep -seconds 17
							
						}
						else {
						
						$VTbody = @{resource = $hash; apikey = $VTApiKey; scan=1}
						$VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/url/report' -Body $VTbody
						
						$myvar += $VTresult
					
						$incre = 1+$incre++

						$MuestrasRestantes = (($resources.Count)-($incre))+1
					
						$tiempo_restantes_segundos = $MuestrasRestantes*1
						$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
						$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
					


                        $totalvendors = $VTresult.total
						$malicioso = $VTresult.positives
                        $Url = $VTresult.url

                        
						If ($malicioso -ge "1"){
								$Fcolormalicioso = "red"
						}
						else{
								$Fcolormalicioso = "Green"
						}

						Write-Host "   [$incre]" -NoNewLine
						Write-Host " URL:" -NoNewLine
						Write-Host " $hash" -ForegroundColor Yellow -NoNewLine
						Write-Host " Vendors:" -NoNewLine
						Write-Host "$totalvendors" -ForegroundColor Yellow -NoNewLine
						Write-Host " [Malicious:" -NoNewLine
						Write-Host "$malicioso" -ForegroundColor $Fcolormalicioso -NoNewLine
						Write-Host " URL:" -NoNewLine
						Write-Host "$url" -ForegroundColor Darkgray -NoNewLine
						Write-Host "]" -NoNewLine
						Write-Host " ($tiemporestanteFormato)" -ForegroundColor Yellow       
						
						Start-Sleep -seconds 1
							
						}
					
				   
				 
				}
		
		
			$CustomRutaURL = "." + $RutaURL
			$myvar | ConvertTo-Json -Depth 10 | Out-File -FilePath $CustomRutaURL      
			$ruta = $PWD
		
			$ficheroExcel = "$ruta\VT-URL-Report.xlsx"
			$CustomRuta = "$ruta" + "$RutaURL"
			$json = Get-Content -Raw $CustomRuta | ConvertFrom-Json
		
			$Excel = New-Object -com Excel.Application
			$Excel.Visible = $false
			$Excel.DisplayAlerts = $false
			
			$Book = $Excel.Workbooks.add()
			$WorkSheet = $Book.Sheets.Item(1)
			$WorkSheet.Name = "VT-URL"


			ForEach($ws in $WorkSheet)

			{

				$ws.Range($ws.Rows(1),$ws.Rows($ws.Rows.Count)).Delete() | Out-null

			}


			$tableRange = $worksheet.Range("A1:H2")
			$table = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,$tableRange,$null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes,$null)

			$table.ListColumns.Item(1).Name = "VirusTotal_Exist"
			$table.ListColumns.Item(2).Name = "resource"
			$table.ListColumns.Item(3).Name = "url"
			$table.ListColumns.Item(4).Name = "total_Vendors"
			$table.ListColumns.Item(5).Name = "Mark as Malicious"
			$table.ListColumns.Item(6).Name = "Scan_date"
			$table.ListColumns.Item(7).Name = "link"
			$table.ListColumns.Item(8).Name = "verbose_msg"

			$table.ListColumns.Item(8).DataBodyRange.NumberFormat = "$#,##0.00"


			$VirusTotalExistS = $json.response_code
			$ResourcesS = $json.resource
			$urlS = $json.url
			$totalS = $json.total
			$positiveS = $json.positives
			$ScanDateS = $json.scan_date
			$linkS = $json.permalink
			$verbosemsgS = $json.verbose_msg
		
			$row = 0
			foreach ($VirusTotalExist in $VirusTotalExistS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,1) = "$VirusTotalExist"
						$table.DataBodyRange.Item($row, 1).HorizontalAlignment = -4108
						
						
					}
			$row = 0
			foreach ($Resources in $ResourcesS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,2) = "$Resources"
						
					}
					
			$row = 0		
			foreach ($url in $urlS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,3) = "$url"		
					}
					
			$row = 0		
			foreach ($total in $totalS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,4) = "$total"		
						if ($total -ge 1){
							$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 15
							$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
							}
						
					}
					
					
			$row = 0		
			foreach ($positive in $positiveS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,5) = "$positive"		
						if ($positive -ge 1){
							$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 3
							$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
							}
						Elseif ($positive -eq 0){
							$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
						}
						Else {
							$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
						}
					}
			
			$row = 0		
			foreach ($ScanDate in $ScanDateS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,6) = "$ScanDate"		
					}
					
			$row = 0		
			foreach ($link in $linkS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,7) = "$link"		
					}
					
			$row = 0		
			foreach ($verbosemsg in $verbosemsgS)
					{
						
						$row++ | Out-null
						$table.DataBodyRange.Item($row,8) = "$verbosemsg"		
					}
				
			$Book.SaveAs($ficheroExcel) 	
			$Book.Close()
			$Excel.Quit()
		
			Write-host ""
			Write-Host " The xlsx file is being generated, wait a few seconds. (" -nonewline 
			write-host "$ficheroExcel" -nonewline -ForegroundColor Green
			write-host ")"
			
			Start-Sleep -seconds 5
            
			pause;
            break
            }	
		4 {
			Clear-Host
			$incre = 0
             
 Write-Host ""
 Write-Host "---------------------------------------------------------------------------------------------"
 Write-Host "---------------------------- CHECKING DOMAIN IN VIRUSTOTAL ----------------------------------"
 Write-Host "---------------------------------------------------------------------------------------------"
 Write-Host ""
 
 #calcular tiempo estimado en segundos
 $tiempoEstimadoSegundos = $resources.Count*17
 
 #mostrar tiempo estimado en formato hh\mm\ss
 $s = $tiempoEstimadoSegundos
 $tiempoEstimadoFormato =  [timespan]::fromseconds($s)

 

 
 
if ($resources.count -ge 4) {
	 
		Write-Warning "[!] Due to the limitation of the free API (4 queries per Minute) this script performs a delay of 17 seconds in each analysis." 
		Write-Host "" 
		
		Write-Host "[>] Estimated time:   " -NoNewLine
		Write-Host -ForegroundColor Yellow -NoNewLine  $tiempoEstimadoFormato
		Write-Host " (hh:mm:ss)" -NoNewLine
		Write-Host ""
	 
	}
else {
		Write-Host "[>] Estimated time:  " -NoNewLine 
		Write-Host -ForegroundColor Yellow -NoNewLine $resources.Count 
		Write-Host -NoNewLine " seconds" 
		Write-Host ""
		
	}


 Write-Host "[>] Total to be analyzed: " -NoNewLine
 Write-Host -ForegroundColor Red -NoNewLine $resources.Count  
 Write-Host -NoNewLine " Domains"  
 Write-Host ""
 Write-Host ""
 
 

	$myvar = @()
        foreach ($hash in $resources)
            {
					## verifica si hay mas de cuatro hashes y añade un sleeptime ya que la api gratuita limita a 4 consultas por minuto(4/min) 
							if ($resources.count -ge 4) {	
							
							$urlVT="https://www.virustotal.com/api/v3/domains/$hash"
							$headers = @{"x-apikey" = $VTApiKey}

							$VTresult=Invoke-RestMethod -Method GET -Uri $urlVT -Headers $headers
							
							$myvar += $VTresult
							
							$incre = 1+$incre++
						
							$MuestrasRestantes = (($resources.Count)-($incre))+1
						
							$tiempo_restantes_segundos = $MuestrasRestantes*17
							$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
							$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
						
									
							$inofensivo = $VTresult.data.attributes.last_analysis_stats.harmless
							$malicioso = $VTresult.data.attributes.last_analysis_stats.malicious
							$sospechoso = $VTresult.data.attributes.last_analysis_stats.suspicious
							$indetectado = $VTresult.data.attributes.last_analysis_stats.undetected
							
							$totalvendors= $inofensivo + $malicioso + $sospechoso + $indetectado
							
							
							If ($inofensivo -ge "1"){
								$Fcolorinofensivo = "green"
							}
							else{
								$Fcolorinofensivo = "DarkGray"
							}							
							
							If ($malicioso -ge "1"){
								$Fcolormalicioso = "red"
							}
							else{
								$Fcolormalicioso = "Green"
							}
							
							If ($sospechoso -eq "0"){
								$Fcolorsospechoso = "Green"
							}
							else{
								$Fcolorsospechoso = "6"
							}
							
							If ($indetectado -ge "0"){
								$Fcolorndetectado = "DarkGray"
							}
							
							
							Write-Host "   [$incre]" -NoNewLine
							Write-Host " DOMAIN:" -NoNewLine
							Write-Host " $hash" -ForegroundColor Yellow -NoNewLine
							Write-Host " Vendors:" -NoNewLine
							Write-Host "$totalvendors" -ForegroundColor Yellow -NoNewLine
							Write-Host " [Malicious:" -NoNewLine
							Write-Host "$malicioso" -ForegroundColor $Fcolormalicioso -NoNewLine
							Write-Host " Suspicious:" -NoNewLine
							Write-Host "$sospechoso" -ForegroundColor $Fcolorsospechoso -NoNewLine
							Write-Host " Harmless:" -NoNewLine
							Write-Host "$inofensivo" -ForegroundColor $Fcolorinofensivo -NoNewLine
							Write-Host " Undetected:" -NoNewLine
							Write-Host "$indetectado" -ForegroundColor $Fcolorndetectado -NoNewLine
							Write-Host "]" -NoNewLine
							Write-Host " ($tiemporestanteFormato)" -ForegroundColor Yellow
							
							
							Start-Sleep -seconds 17
						
					}
                    else {
					
						
							$urlVT="https://www.virustotal.com/api/v3/domains/$hash"
							$headers = @{"x-apikey" = $VTApiKey}

							$VTresult=Invoke-RestMethod -Method GET -Uri $urlVT -Headers $headers
							
							$myvar += $VTresult
							
							$incre = 1+$incre++
						
							$MuestrasRestantes = (($resources.Count)-($incre))+1
						
							$tiempo_restantes_segundos = $MuestrasRestantes*1
							$TiempoRestante = ($tiempoEstimadoSegundos)-($tiempo_restantes_segundos)
							$tiemporestanteFormato =  [timespan]::fromseconds($tiempo_restantes_segundos)
						
									
							$inofensivo = $VTresult.data.attributes.last_analysis_stats.harmless
							$malicioso = $VTresult.data.attributes.last_analysis_stats.malicious
							$sospechoso = $VTresult.data.attributes.last_analysis_stats.suspicious
							$indetectado = $VTresult.data.attributes.last_analysis_stats.undetected
							
							$totalvendors= $inofensivo + $malicioso + $sospechoso + $indetectado
							
							
							If ($inofensivo -ge "1"){
								$Fcolorinofensivo = "green"
							}
							else{
								$Fcolorinofensivo = "DarkGray"
							}							
							
							If ($malicioso -ge "1"){
								$Fcolormalicioso = "red"
							}
							else{
								$Fcolormalicioso = "Green"
							}
							
							If ($sospechoso -eq "0"){
								$Fcolorsospechoso = "Green"
							}
							else{
								$Fcolorsospechoso = "6"
							}
							
							If ($indetectado -ge "0"){
								$Fcolorndetectado = "DarkGray"
							}
							
							
							Write-Host "   [$incre]" -NoNewLine
							Write-Host " DOMAIN:" -NoNewLine
							Write-Host " $hash" -ForegroundColor Yellow -NoNewLine
							Write-Host " Vendors:" -NoNewLine
							Write-Host "$totalvendors" -ForegroundColor Yellow -NoNewLine
							Write-Host " [Malicious:" -NoNewLine
							Write-Host "$malicioso" -ForegroundColor $Fcolormalicioso -NoNewLine
							Write-Host " Suspicious:" -NoNewLine
							Write-Host "$sospechoso" -ForegroundColor $Fcolorsospechoso -NoNewLine
							Write-Host " Harmless:" -NoNewLine
							Write-Host "$inofensivo" -ForegroundColor $Fcolorinofensivo -NoNewLine
							Write-Host " Undetected:" -NoNewLine
							Write-Host "$indetectado" -ForegroundColor $Fcolorndetectado -NoNewLine
							Write-Host "]" -NoNewLine
							Write-Host " ($tiemporestanteFormato)" -ForegroundColor Yellow
							
							
							Start-Sleep -seconds 1
					
						
					}
                
               
             
            }

		
		$export = $myvar
	
		
		$CustomRutaIP = "." + $RutaDomain
		$export | ConvertTo-Json -Depth 10 | Out-File -FilePath $CustomRutaIP
		$ruta = $PWD
	
		$ficheroExcel = "$ruta\VT-DOMAIN-Report.xlsx"
		$CustomRuta = "$ruta" + "$RutaDomain"
		$json = Get-Content -Raw $CustomRuta | ConvertFrom-Json
	
		$Excel = New-Object -com Excel.Application
		$Excel.Visible = $false
		$Excel.DisplayAlerts = $false
		
		$Book = $Excel.Workbooks.add()
		$WorkSheet = $Book.Sheets.Item(1)
		$WorkSheet.Name = "VT-DOMAIN"


		ForEach($ws in $WorkSheet)

		{

			$ws.Range($ws.Rows(1),$ws.Rows($ws.Rows.Count)).Delete() | Out-null

		}


		$tableRange = $worksheet.Range("A1:I2")
		$table = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,$tableRange,$null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes,$null)

		$table.ListColumns.Item(1).Name = "Scan Resource"
		$table.ListColumns.Item(2).Name = "harmless"
		$table.ListColumns.Item(3).Name = "malicious"
		$table.ListColumns.Item(4).Name = "suspicious"
		$table.ListColumns.Item(5).Name = "undetected"
		$table.ListColumns.Item(6).Name = "creation_date"
		$table.ListColumns.Item(7).Name = "last_analysis_date"
		$table.ListColumns.Item(8).Name = "last_dns_records_date"
		$table.ListColumns.Item(9).Name = "link"

		$table.ListColumns.Item(9).DataBodyRange.NumberFormat = "$#,##0.00"


		$ScanResourceS = $json.data.id
		$harmlessS = $json.data.attributes.last_analysis_stats.harmless
		$maliciousS = $json.data.attributes.last_analysis_stats.malicious
		$suspiciousS = $json.data.attributes.last_analysis_stats.suspicious
		$undetectedS = $json.data.attributes.last_analysis_stats.undetected
		$creationDateS = $json.data.attributes.creation_date
		$last_analysis_dateS = $json.data.attributes.last_analysis_date
		$last_dns_records_dateS = $json.data.attributes.last_dns_records_date
		$linkS = $json.data.id
		
		
		
		
		
		foreach ($ScanResource in $ScanResourceS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,1) = "$ScanResource"
					
					
				}
		$row = 0
		foreach ($harmless in $harmlessS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,2) = "$harmless"
					
				}
				
		$row = 0		
		foreach ($malicious in $maliciousS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,3) = "$malicious"		
					if ($malicious -ge 1){
						$table.DataBodyRange.Item($row,3).Interior.ColorIndex = 3
						$table.DataBodyRange.Item($row, 3).HorizontalAlignment = -4108
						}
					Else {
						$table.DataBodyRange.Item($row,3).Interior.ColorIndex = 4
						$table.DataBodyRange.Item($row, 3).HorizontalAlignment = -4108
					}
				}
				
		$row = 0		
		foreach ($suspicious in $suspiciousS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,4) = "$suspicious"
					if ($suspicious -ge 1){
						$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 46
						$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
						}
					Elseif ($suspicious -eq 0){
							$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
						}
					Else {
						$table.DataBodyRange.Item($row,4).Interior.ColorIndex = 4
						$table.DataBodyRange.Item($row, 4).HorizontalAlignment = -4108
					}
				}
				
		$row = 0		
		foreach ($undetected in $undetectedS)
				{
					
					$row++ | Out-null
					$table.DataBodyRange.Item($row,5) = "$undetected"
					if ($undetected -ge 1){
						$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 15
						$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
						}
						
					Elseif ($undetected -eq 0){
							$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 4
							$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
						}
					Else {
						$table.DataBodyRange.Item($row,5).Interior.ColorIndex = 4
						$table.DataBodyRange.Item($row, 5).HorizontalAlignment = -4108
					}
				}
				
		$row = 0		
		foreach ($creationDate in $creationDateS)
				{
					
					$row++ | Out-null
					$FormatoCreacion =[DateTimeOffset]::FromUnixTimeSeconds($creationDate).ToString('yyyy-MM-dd')
					$table.DataBodyRange.Item($row,6) = "$FormatoCreacion"
					
				}
				
		$row = 0		
		foreach ($last_analysis_date in $last_analysis_dateS)
				{
					
					$row++ | Out-null
					$FormatoLastAnalysis =[DateTimeOffset]::FromUnixTimeSeconds($last_analysis_date).ToString('yyyy-MM-dd')
					$table.DataBodyRange.Item($row,7) = "$FormatoLastAnalysis"
					
				}
				
		$row = 0		
		foreach ($last_dns_records_date in $last_dns_records_dateS)
				{
					
					$row++ | Out-null
					$FormatoLastDNS =[DateTimeOffset]::FromUnixTimeSeconds($last_dns_records_date).ToString('yyyy-MM-dd')
					$table.DataBodyRange.Item($row,8) = "$FormatoLastDNS"
					
				}
				
			
		$row = 0		
		foreach ($link in $linkS)
				{
					$row++ | Out-null
					$table.DataBodyRange.Item($row,9) = "https://www.virustotal.com/gui/domain/$link"
					
					
				}
				
			$Book.SaveAs($ficheroExcel) 
			
			$Book.Close()
			$Excel.Quit()
			
			
			

			Write-host ""
			Write-Host " The xlsx file is being generated, wait a few seconds. (" -nonewline 
			write-host "$ficheroExcel" -nonewline -ForegroundColor Green
			write-host ")"
			
			Start-Sleep -seconds 5
		
		

	

			
            pause; 
            break
        }
		
        5 {"Exit"; break}
        default {Write-Host -ForegroundColor red -BackgroundColor white "Invalid option. Select another option";pause}
        
    }
 
showmenu
}





