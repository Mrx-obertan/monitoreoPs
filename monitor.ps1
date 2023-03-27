# Define las variables de búsqueda de eventos
$LogName = "Security"
$Keywords = @(4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4702, 4719)

# Obtener eventos del registro de seguridad
$Events = Get-EventLog -LogName $LogName -InstanceId $Keywords -Newest 1000

# Analizar los eventos para detectar posibles ataques
foreach ($Event in $Events) {
    $EventMessage = $Event.Message
    if ($EventMessage -match "Failed login" -or
        $EventMessage -match "Logon Type 3" -or
        $EventMessage -match "New Logon") {
        # El evento indica un intento fallido de inicio de sesión o un inicio de sesión exitoso
        Write-Host "Posible ataque de inicio de sesión detectado:"
        Write-Host $EventMessage
    }
    if ($EventMessage -match "Successful Logon" -and $Event.ReplacementStrings[5] -eq "SYSTEM") {
        # El evento indica un inicio de sesión exitoso del usuario SYSTEM, que podría ser una señal de compromiso
        Write-Host "Posible compromiso detectado:"
        Write-Host $EventMessage
    }
}
