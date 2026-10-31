namespace SafeUpload.Agent.Service.Interception;

internal static class FileQuarantine
{
    /// <summary>
    /// Move o arquivo bloqueado para a quarentena.
    ///
    /// Mover, e não apagar: o arquivo é do usuário, e o agente não tem mandato
    /// para destruí-lo. Ele sai do destino monitorado, que é o que a política
    /// exige, e continua recuperável.
    /// </summary>
    internal static bool TryMove(string path, string targetDirectory, ILogger logger)
    {
        try
        {
            var name = Path.GetFileNameWithoutExtension(path);
            var extension = Path.GetExtension(path);
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var target = Path.Combine(targetDirectory, $"{name}-{stamp}{extension}");

            // Nomes iguais no mesmo segundo: um sufixo numérico resolve sem
            // sobrescrever o arquivo que já está na quarentena.
            var attempt = 1;
            while (File.Exists(target))
            {
                target = Path.Combine(targetDirectory, $"{name}-{stamp}-{attempt}{extension}");
                attempt++;
            }

            File.Move(path, target);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // O veredito continua valendo e o evento continua sendo auditado;
            // só o arquivo permanece onde está.
            try { logger.LogWarning("Movimentacao para a pasta de bloqueados nao confirmada ({Kind}, HRESULT {HResult}).", ex.GetType().Name, ex.HResult); }
            catch { /* A logging failure must not change the file outcome. */ }
            return false;
        }
    }

}
