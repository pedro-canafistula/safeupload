CREATE DATABASE IF NOT EXISTS app;

USE app;

CREATE TABLE IF NOT EXISTS hosts (
    id_host INT PRIMARY KEY AUTO_INCREMENT,
    ip VARCHAR(15),
    mascara INT CHECK(mascara BETWEEN 0 AND 32),
    hostname VARCHAR(100),
    sistema_operacional VARCHAR(40),
    versao_so VARCHAR(20),
    fabricante VARCHAR(50),
    modelo VARCHAR(50),
    mac_address VARCHAR(20),
    numero_serie VARCHAR(30),
    visto_por_ultimo TIMESTAMP(6),
    ativo INT CHECK (ativo IN (0,1))
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS usuarios_so (
    id_usuario_so INT PRIMARY KEY AUTO_INCREMENT,
    sid VARCHAR(50),
    usuario_so VARCHAR(40) NOT NULL,
    dominio VARCHAR(50),
    admin INT,
    fk_id_host INT NOT NULL,
    CONSTRAINT fk_id_host_01 FOREIGN KEY (fk_id_host) REFERENCES hosts (id_host)
    ON DELETE CASCADE
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;


CREATE TABLE IF NOT EXISTS regras (
    id_regras INT PRIMARY KEY AUTO_INCREMENT,
    bloquear_cpf INT CHECK(bloquear_cpf IN (0,1)),
    bloquear_cnpj INT CHECK(bloquear_cnpj IN (0,1)),
    bloquear_rg INT CHECK(bloquear_rg IN (0,1)),
    bloquear_dados_bancarios INT CHECK(bloquear_dados_bancarios IN (0,1)),
    bloquear_cartao_credito INT CHECK(bloquear_cartao_credito IN (0,1)),
    bloquear_credenciais INT CHECK(bloquear_credenciais IN (0,1)),
    bloquear_dados_saude INT CHECK(bloquear_dados_saude IN (0,1)),
    bloquear_dados_pessoais INT CHECK(bloquear_dados_pessoais IN (0,1)),
    bloquear_documentos_confidenciais INT CHECK(bloquear_documentos_confidenciais IN (0,1))
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;


CREATE TABLE IF NOT EXISTS politicas (
    id_politica INT PRIMARY KEY AUTO_INCREMENT,
    versao VARCHAR(20),
    nome VARCHAR(50),
    fk_id_host INT NOT NULL,
    acao VARCHAR(10),
    fk_id_regras INT,
    criadaEm TIMESTAMP,
    origem VARCHAR(30),
    CONSTRAINT fk_id_host_02 FOREIGN KEY (fk_id_host) REFERENCES 
    hosts (id_host),
    CONSTRAINT fk_id_regras FOREIGN KEY (fk_id_regras) REFERENCES
    regras (id_regras)
)ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;


CREATE TABLE IF NOT EXISTS solicitacoes (
    id_solicitacao INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_usuario_so INT,
    fk_id_empresa_designada INT,
    fk_id_admin_designado INT,
    descricao LONGTEXT NOT NULL,
    status INT CHECK (status BETWEEN 0 AND 4)
        COMMENT '0=designado, 1=pendente, 2=em andamento, 3=recusado, 4=concluído',
    CONSTRAINT fk_id_usuario_so FOREIGN KEY (fk_id_usuario_so) REFERENCES usuarios_so(id_usuario_so)
        ON DELETE SET NULL,
    CONSTRAINT fk_id_empresa_designada FOREIGN KEY (fk_id_empresa_designada) REFERENCES acesso.empresas(id_empresa)
        ON DELETE SET NULL,
    CONSTRAINT fk_id_admin_designado FOREIGN KEY (fk_id_admin_designado) REFERENCES acesso.usuarios(id_usuario)
        ON DELETE SET NULL
)ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS agent_audit_ingest (
    record_key VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    event_id VARCHAR(36) NOT NULL,
    endpoint_id VARCHAR(255) NOT NULL,
    occurred_at_utc TIMESTAMP(6) NOT NULL,
    received_at_utc TIMESTAMP(6) NOT NULL,
    schema_version INT NOT NULL,
    sender_hostname VARCHAR(255),
    agent_version VARCHAR(200),
    payload LONGTEXT NOT NULL,
    INDEX idx_agent_audit_event (event_id),
    INDEX idx_agent_audit_endpoint_time (endpoint_id, occurred_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;