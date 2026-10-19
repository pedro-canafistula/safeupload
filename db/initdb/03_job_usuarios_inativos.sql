USE app;

CREATE EVENT ev_atualizar_status_usuarios_so
ON SCHEDULE EVERY 11 MINUTE
DO
    UPDATE usuarios_so
    SET ATIVO = 0 
    WHERE visto_por_ultimo < NOW() - INTERVAL 11 MINUTE;