-- Dados do Centro de Administração: máquinas, políticas, grupos e auditoria.
-- Cada linha pertence a uma empresa (acesso.empresas.id_empresa); o backend só mostra a empresa do usuário.
-- Não há migrations: para mudar o schema, recrie o banco de desenvolvimento.
CREATE DATABASE IF NOT EXISTS app;

USE app;

CREATE TABLE IF NOT EXISTS politicas (
    id_politica INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_empresa INT NOT NULL,
    nome VARCHAR(80) NOT NULL,
    padrao TINYINT NOT NULL DEFAULT 0 CHECK (padrao IN (0,1)),
    UNIQUE KEY uk_politica_nome (fk_id_empresa, nome)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Cada edição cria uma versão; id_versao é a "version" que o agente recebe.
CREATE TABLE IF NOT EXISTS politica_versoes (
    id_versao INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_politica INT NOT NULL,
    configuracao LONGTEXT NOT NULL,
    criada_em TIMESTAMP(6) NOT NULL,
    criada_por VARCHAR(75) NOT NULL,
    usa_regras TINYINT NOT NULL DEFAULT 0 CHECK (usa_regras IN (0,1)),
    CONSTRAINT fk_versao_politica FOREIGN KEY (fk_id_politica) REFERENCES politicas (id_politica) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Regras personalizadas: "definicao" guarda o formulário do console (condições e exemplos), já validado.
CREATE TABLE IF NOT EXISTS regras_personalizadas (
    id_regra INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_empresa INT NOT NULL,
    nome VARCHAR(80) NOT NULL,
    descricao VARCHAR(300),
    definicao LONGTEXT NOT NULL,
    revisao INT NOT NULL,
    atualizada_em TIMESTAMP(6) NOT NULL,
    atualizada_por VARCHAR(75) NOT NULL,
    UNIQUE KEY uk_regra_nome (fk_id_empresa, nome)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS grupos (
    id_grupo INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_empresa INT NOT NULL,
    nome VARCHAR(80) NOT NULL,
    fk_id_politica INT NULL,
    UNIQUE KEY uk_grupo_nome (fk_id_empresa, nome),
    CONSTRAINT fk_grupo_politica FOREIGN KEY (fk_id_politica) REFERENCES politicas (id_politica)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- hostname, ip, sistema etc. são informados pelo próprio agente e só servem para exibição.
CREATE TABLE IF NOT EXISTS hosts (
    id_host INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_empresa INT NOT NULL,
    fk_id_grupo INT NULL,
    chave_publica TEXT NOT NULL,
    hostname VARCHAR(100),
    ip VARCHAR(45),
    mascara INT,
    sistema_operacional VARCHAR(60),
    versao_so VARCHAR(40),
    mac_address VARCHAR(20),
    versao_agente VARCHAR(50),
    formato_regras INT NOT NULL DEFAULT 0,
    politica_aplicada INT NULL,
    cadastrado_em TIMESTAMP(6) NOT NULL,
    visto_por_ultimo TIMESTAMP(6) NULL,
    revogado_em TIMESTAMP(6) NULL,
    INDEX idx_hosts_empresa (fk_id_empresa),
    CONSTRAINT fk_host_grupo FOREIGN KEY (fk_id_grupo) REFERENCES grupos (id_grupo) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Tokens de cadastro: uso único, válidos por 15 minutos (conferido pelo backend).
CREATE TABLE IF NOT EXISTS tokens (
    id_token INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_empresa INT NOT NULL,
    token VARCHAR(8) NOT NULL UNIQUE,
    criado_em TIMESTAMP(6) NOT NULL,
    criado_por VARCHAR(75) NOT NULL,
    usado_em TIMESTAMP(6) NULL,
    fk_id_host INT NULL,
    CONSTRAINT fk_token_host FOREIGN KEY (fk_id_host) REFERENCES hosts (id_host) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Eventos e justificativas enviados pelos agentes. fk_id_host vem da assinatura, nunca do corpo.
CREATE TABLE IF NOT EXISTS agent_audit_ingest (
    record_key VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    event_id VARCHAR(36) NOT NULL,
    fk_id_host INT NOT NULL,
    endpoint_id VARCHAR(255) NOT NULL,
    occurred_at_utc TIMESTAMP(6) NOT NULL,
    received_at_utc TIMESTAMP(6) NOT NULL,
    schema_version INT NOT NULL,
    sender_hostname VARCHAR(255),
    agent_version VARCHAR(200),
    payload LONGTEXT NOT NULL,
    INDEX idx_agent_audit_event (event_id),
    INDEX idx_agent_audit_host_time (fk_id_host, occurred_at_utc),
    INDEX idx_agent_audit_time (kind, occurred_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
