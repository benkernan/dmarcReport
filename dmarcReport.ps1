<#
.SYNOPSIS
  Check that all servers in the server tracker have backups set for them.
.DESCRIPTION
  Postmark only holds 2 weeks worth of reports for us.
.EXAMPLE
  .\veeam_backup_check.ps1
.INPUTS
  Inputs (if any)
.OUTPUTS
  Output (if any)
.NOTES
  General notes
#>
Param (
   [Parameter(Mandatory=$true)]
   [string]$startDate,
   [Parameter(Mandatory=$true)]
   [string]$endDate,
   [Parameter(Mandatory=$true)]
   [string]$APIToken
)

# setting the timedate pattern to match postmark's requirements
$currentThread = [System.Threading.Thread]::CurrentThread
$culture = [CultureInfo]::InvariantCulture.Clone()
$culture.DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
$currentThread.CurrentCulture = $culture
$currentThread.CurrentUICulture = $culture

$method = "GET"
$scriptPath = "$PSScriptRoot"

#not ready for this yet
#$jsonPath = "$scriptPath/dmarcReports/$startDate_to_$endDate"
#$jsonFile = "$jsonPath/allDMARC$startDate_to_$endDate.json"

#if(-not (Test-Path $jsonPath)) {
#  try {
#      New-Item -path "$jsonPath" -type directory
#  }
#  catch {
#      Write-Host "Logging Directory $jsonPath can't be created"
#  }
#}
#write-host "Pulling JSON DMARC report for dates $startDate and $endDate"

$start = [Datetime]$startDate
$start = $start.ToShortDateString()
$end = [Datetime]$startDate
  $end = $end.AddDays(1)
  $end = $end.ToShortDateString()
$realEnd = [Datetime]$endDate
$realEnd = $realEnd.ToShortDateString()


write-host -foregroundColor Green "
Processing $start to $realEnd"

while ($start -ne $realEnd) {
  write-host -foregroundColor Yellow "
Querying Report for $start to $end"
 $allReports = Invoke-RestMethod -uri "https://dmarc.postmarkapp.com/records/my/reports?from_date=$start&to_date=$end&limit=100" -Method $method -Headers @{'X-Api-Token' = "$APIToken"} -UseBasicParsing
 $dmarcReport = $allReports.entries

  #This function iterates through all the reports in the timeframe  and outputs the individual report.
  foreach ($rep in $dmarcReport){
    write-host -foregroundColor red $rep.created
      $reportID = $rep.id
      #$eachReport = "$jsonPath/$reportID.json"
      $getReport = Invoke-RestMethod -uri https://dmarc.postmarkapp.com/records/my/reports/$reportID -Method $method -Headers @{'X-Api-Token' = "$APIToken"} -UseBasicParsing
      $j = @($getReport.records.row_num) #get the value for row_num
      $max = $j | Measure-Object -Maximum #get the max row number.
      $i = 0
      $j = ($max.Maximum)-1 #set the variale to the max value
      #$j = $j-1
      while ($i -le ($j)){
        $orgName = $getReport.organization_name
        $records = $getReport.records[$i]
        $testIP = $getReport.records[$i].source_ip

        $iAdjust = $i+1
        $jAdjust = $j+1
        write-host "$reportID : $iAdjust of $jAdjust for $testIP"
        # Formatting and output the specific info that we want to find out why SPF is failing
        $object += @(foreach ($record in $records) {
          $score = 0
          $total++
          $reason = ''
            if (($record.policy_evaluated_spf -eq "fail") -and ($record.header_from -ne $record.spf_domain)) {
                $reason = "1. SPF Failed because Header_From and Return-Path do not match. "
                $score = $score+1
            }
            if (($record.policy_evaluated_dkim -eq "fail") -and ($record.header_from -ne $record.dkim_domain)) {
              $reason += "2. DKIM failed because Header_From and DKIM Domain do not match. "
              $score = $score+2
            }
            if (($record.policy_evaluated_spf -eq "pass") -and ( $record.policy_evaluated_dkim -eq "pass")) {
              $reason += "0. Perfect!"
            }
            if ($score -eq 3 ){
              $dmarcResult = "Fails DMARC"
              $failedEmails += $record.count
            }
            elseif ($score -lt 3 ) {
              $dmarcResult = "Passes DMARC"
            }
            else {
              $dmarcResult = "Inconclusive"
            }
            $totalEmails += $record.count
            $spfReport = New-Object -Type PsObject -Property @{
                'id' = $reportID
                'emailsInReport' = $record.count
                'row_num' = "$iAdjust of $jAdjust"
                'reportingOrg' = $orgName # which ISP / service reported

                'SPFpolicyEval' = $record.policy_evaluated_spf # DMARC's Enhanced SPF check - looks at both the spf_result and if the header_from and return-match match
                'DKIMpolicyEval' = $record.policy_evaluated_dkim # DMARC's enhanced DKIM check - the DKIM domain and From domain's must match. May not match for some systems.
                #'dkimReasonType' = $record.policy_evaluated_reason_type # this is what our DMARC policy is set to. Currently None.
                'returnPath' = $record.spf_domain # spf domain
                'basicSPFResult' = $record.spf_result # Check for if the IP is listed in the SPF record
                'dkimDomain' = $record.dkim_domain
                'basicDKIMResult' = $record.dkim_result # Check if the DKIM matches

                'headerFrom' = $record.header_from # payload from domain
                'sourceIP' = $record.source_ip # connecting IP
                'hostName' = $record.host_name # reverse DNS result of connecting IP
                'topPrivateDomain' = $record.top_private_domain_name # ??????????????????
                'dmarcResult' = $dmarcResult
                'reason' = $reason

            }
            $spfReport
        })
        $i++
      }
  }
  $start = [Datetime]$start
  $start = $start.AddDays(1)
  $start = $start.ToShortDateString()
  $end = [Datetime]$end
  $end = $end.AddDays(1)
  $end = $end.ToShortDateString()
}

#summary
write-host "Total number of Reports: $total"
write-host "Total Emails: $totalEmails"
write-host "Failed DMARC: $failedEmails"
$DMARCScore = ($failedEmails/$totalEmails)*100
$didTheMath = [math]::Round($DMARCScore,2)
write-host "DMARC Failure %: $didTheMath"

#showing where dmarc fails highlights where SPF / DKIM are not passing. We need to investigate these ones.
$object | sort-object topPrivateDomain,sourceIP | select-object -Property id,emailsInReport,row_num,reportingOrg,SPFpolicyEval,DKIMpolicyEval,returnPath,basicSPFResult,dkimDomain,basicDKIMResult,headerFrom,sourceIP,hostName,topPrivateDomain,dmarcResult,reason | out-gridview