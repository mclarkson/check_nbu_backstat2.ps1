#
# ///// check_nbu_backstat2.ps1 v1.2 2011-06-01 /////
#
# Ver. 1.0 - New creation
# Ver. 1.1 - Add the NetBackup return code in Nagios message
# Ver. 1.2 - Heavily Modified (Mark Clarkson 2011-11-08)
#            Now based on NB Policy
#            Updated nbuerror.csv
#
# Check Symantec NetBackup - Backup Job Status
#
# Original Author: Ryosuke Matsui ryosuke.matsui@x-edges.com
#
# This PowerShell script works with NSClient++ on MS-Windows environment.
#
#---------------------------------------------------------------------------
# << Distribution Files >>
# 1. check_nbu_backstat.ps1 <-- this script
# 2. nbuerror.csv           <-- CSV file described the NBU status codes
#
#---------------------------------------------------------------------------
# << How To Install >>
# [check_nbu_backstat.ps1 Settings]
# 1. Copy "check_nbu_backstat.ps1" and "nbuerror.csv"
#    into the scripts folder of NSClient++
#    (C:\Program Files\NSClient++\scripts).
# 2. Modify / Check the values of $nbuBin and $statFile
#    if you need.
# 3. Modify / Add the "RETURN CODE TABLE SETTING"
#    in the "searchRtnStat" function if you need.
#
# [NSClient++ Settings]
# 4. Add the following setting in the [Wrapped Scripts]
#    section in the "NSC.ini".
# OR
# [External Scripts]
# check_netbackup=cmd /c echo scripts/check_nbu_backstat.ps1 -nbpolicy $ARG1$ -hours $ARG2$; exit($lastexitcode) | powershell.exe -command - 
# powershell_ok=cmd /c echo echo 'Test OK'; exit 0; | powershell.exe -command -

# 5. Enable the following settings in the "NSC.ini".
#    - port=5666
#    - command_timeout=60
#    - allow_arguments=1
#    - allow_nasty_meta_chars=1
#    - script_dir=scripts\
#    - socket_timeout=30
#    - allowed_hosts=xxx.xxx.xxx.xxx/xx
# 6. Restart the "NSClient++" service.
#
# [Nagios Settings]
# 7. Add the following setting to Nagios "commands".
#    $USER1$/check_nrpe -H $HOSTADDRESS$ -c check_nbu_backup -a $ARG1$
# 8. Add new Nagios "service" to check status of the backup job.
#    * The backup client name that you want to check the latest backup
#      status have to be set to $ARG1$ in the "service" setting.
#
#---------------------------------------------------------------------------
#

param( [string]$nbpolicy, [Int]$hours )

#---------------------------------------------------------------------------
# User Modifyable Section
#---------------------------------------------------------------------------

if( $hours -eq $null ) {
    $global:hours = 24
} else {
    $global:hours = $hours
}

# NetBackup ADMIN COMMAND PATH (Modify if you need)
$nbuBin = "C:\Program Files\Veritas\NetBackup\bin\admincmd"

# NetBackup ERROR STATUS DEFINITION FILE (Modify if you need)
$statFile = "C:\'Program Files'\NSClient++\scripts\nbuerror.csv"

#---------------------------------------------------------------------------
# Don't modify anything below
#---------------------------------------------------------------------------

# Ensure output doesn't wrap at 80 columns
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (500, 25)

#---------------------------------------------------------------------------
# Global Variables
#---------------------------------------------------------------------------

# RETURN STATUS VALUES FOR Nagios
$stateOk = 0
$stateWarning = 1
$stateCritical = 2
$stateUnknown = 3

$stateText = @{ $stateOk = "OK: "
                $stateWarning = "WARNING: "
                $stateCritical = "CRITICAL: "
                $stateUnknown = "UNKNOWN: " }

$defaultexitcode = $stateWarning

# NetBackup Status values
$jobState = @{ 0 = "Queued"
               1 = "Active"
               2 = "Re-Queued"
               3 = "Done"
               4 = "Suspended"
               5 = "Incomplete" }

$schedtype = @{ 0 = "Full"
                1 = "Incr"
                2 = "UserBackup"
                3 = "UserArchive"
                4 = "Cumulative-Incr" }

#---------------------------------------------------------------------------
# Functions
#---------------------------------------------------------------------------

#---------------------------------------------------------------------------
function trunc( [String] $str, [int] $l )
#---------------------------------------------------------------------------
# Limit $str to $l characters by truncating the rest.
# Returns the truncated string.
{
    if( $str.length -gt $l ) { 
        return $str.remove($l)
    } else {
        return $str
    }
}

#---------------------------------------------------------------------------
function arg_check()
#---------------------------------------------------------------------------
{
    if ($nbpolicy -eq "")
    {
        $scriptName = $MyInvocation.MyCommand.Name
        $msg = "Usage: $scriptName -nbpolicy [NetBackup Policy]"
        "{0}{1}" -f $stateText[$stateUnknown], $msg
        exit $stateUnknown
    }
}

#---------------------------------------------------------------------------
function searchRtnStat([int] $x)
#---------------------------------------------------------------------------
{
    if( $x -eq $null ) { return; }

    $rtnStatTab = @{}

    # RETURN CODE TABLE SETTING
    # - Key   --> NetBackup return code
    # - Value --> Nagios retrun code (0,1,2,3)
    #           * "Values" should be
    #              $stateOK, $stateWarning and $stateUnknow only.
    #           * Default key-value is set to $stateCritical.

    $rtnStatTab[0] = $stateOk
    $rtnStatTab[1] = $stateWarning

    return ($rtnStatTab[$x])
}

#---------------------------------------------------------------------------
function fill_backuplist()
#---------------------------------------------------------------------------
{
    $curtime = [int]((Get-Date -UFormat %s) -Replace("[,\.]\d*", ""))
    $after = $curtime - (60*60*$global:hours)
    $status = 0

    # Get a list of backups
    $backuplist = &"$nbuBin\bpdbjobs" -most_columns | %{
        $res=@{}
        $var=$_.Split(',')
        # var: 1-jobtype, 4-class, 10-ended 
        if( $var[4] -match $nbpolicy -and $var[1] -eq 0 `
            -and $var[10] -gt $after )
        {
            $res.jobid, $res.jobtype, $res.state, $res.status, $res.class,
            $res.schedule, $res.client, $res.server, $res.started, $res.elapsed,
            $res.ended, $res.stunit, $res.try, $res.operation, $res.kbytes,
            $res.files, $res.pathlastwritten, $res.percent, $res.jobpid,
            $res.owner, $res.subtype, $res.classtype, $res.schedule_type,
            $res.priority, $res.group, $res.masterserver, $res.retentionunits,
            $res.retentionperiod, $res.compression, $res.kbyteslastwritten,
            $res.fileslastwritten, $res.trystatus, $res.trystatusdescription,
            $res.parentjob, $res.kbpersec, $res.copy, $res.robot, $res.vault,
            $res.profile, $res.session, $res.ejecttapes, $res.srcstunit,
            $res.srcserver, $res.srcmedia, $res.dstmedia, $res.stream,
            $res.suspendable, $res.resumable, $res.restartable, $res.datamovement,
            $res.snapshot, $res.backupid, $res.killable, $res.controllinghost =
            $var[0..53]

            if( $res.status -ne "0" ) { $status = [Int]$res.status }

            $res
        }
    }

    return $backuplist, $status
}

#---------------------------------------------------------------------------
function display_nagios_status( $exitCode, $nbstatus )
#---------------------------------------------------------------------------
{
    "{0}{1}" -f $stateText[$exitCode], $errtable["$nbstatus"]
}

#---------------------------------------------------------------------------
function display_state_table()
#---------------------------------------------------------------------------
{
    #"{0,-6} {1,-10} {3,-20} {4,-10} {5,-10} {2}" `
    "`n{0,-6} {1,-10} {3,-20} {5,-10} {2}" `
      -f "JOBID", "CLIENT", "STATUS", "CLASS", "STATE", "SCHEDTYPE"
    $backuplist | 
        ForEach-Object {
            [string]$client = trunc $_.client 10 
            [string]$class = trunc $_.class 20 
            [string]$sched = trunc ($schedtype[[int]$_.schedule_type]) 10 
            $desc = $errtable[$_.status]
            #"{0,-6} {1,-10} {3,-20} {4,-10} {5,-10} ({2}) {6}" `
            "{0,-6} {1,-10} {3,-20} {5,-10} ({2}) {6}" `
            -f $_.jobid, $client, $_.status, $class, `
               $jobState[[int]$_.state], $sched, $desc
        } | Select-String -notmatch "\(0\)" | Select-Object -first 5
    "..."
}

#---------------------------------------------------------------------------
function fill_errtable()
#---------------------------------------------------------------------------
{
    [hashtable]$errtable = @{}

    # NetBackup ERROR STATUS TABLE BUILD
    $importcsv = "Import-Csv -path $statFile"
    foreach ($item in Invoke-Expression $importcsv)
    {
        $errtable[$item.Status] = $item.Description
    }

    return [hashtable]$errtable
}

#---------------------------------------------------------------------------
function set_exitcode_from_nb_status()
#---------------------------------------------------------------------------
{
    # Nagios RETURN STATUS
    $nagiosStatCode = searchRtnStat($nbstatus)
    if ($nagiosStatCode -ne $null)
    {
        return $nagiosStatCode
    }

    return $defaultexitcode
}

#---------------------------------------------------------------------------
function main()
#---------------------------------------------------------------------------
#
# TODO: Nothing-backed-up check maybe
#
{
    arg_check
    $backuplist, $nbstatus = fill_backuplist
    $errtable = fill_errtable
    $exitCode = set_exitcode_from_nb_status

    display_nagios_status $exitCode $nbstatus
    if( $exitCode -ne $stateOk ) { display_state_table }

    exit $exitCode
}

#---------------------------------------------------------------------------
# Execution starts
#---------------------------------------------------------------------------
main


