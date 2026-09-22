CREATE DATABASE IF NOT EXISTS app;

USE app;

CREATE TABLE IF NOT EXISTS hosts (
    id_host INT PRIMARY KEY,
    hostname VARCHAR(30),
    ip VARCHAR(15) NOT NULL,
    sistema_operacional VARCHAR(40),
    versao_so VARCHAR(20),
    fabricante VARCHAR(50),
    modelo VARCHAR(50),
    mac_address VARCHAR(20),
    numero_serie VARCHAR(30)
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS usuarios_so (
    id_usuario_so INT PRIMARY KEY,
    sid VARCHAR(50),
    usuario_so VARCHAR(40) NOT NULL,
    dominio VARCHAR(50),
    admin BOOLEAN,
    ativo BOOLEAN,
    fk_id_host INT,
    CONSTRAINT fk_id_host_01 FOREIGN KEY (fk_id_host) REFERENCES hosts (id_host)
    ON DELETE CASCADE
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS objetos (
    id_objeto INT PRIMARY KEY,
    caminho_completo VARCHAR(400),
    nome_objeto VARCHAR(200),
    extensao VARCHAR(7),
    tamanho_bytes BIGINT,
    data_hora_criacao DATETIME,
    data_hora_modificacao DATETIME,
    fk_id_proprietario INT,
    CONSTRAINT fk_id_usuario_so_01 FOREIGN KEY (fk_id_proprietario) REFERENCES usuarios_so (id_usuario_so)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS regras (
    id_regras INT PRIMARY KEY,
    bloquear_senhas BOOLEAN,
    bloquear_tokens BOOLEAN,
    bloquear_cpf BOOLEAN,
    bloquear_numero_cartao BOOLEAN,
    timeout INT,
    tamanho_limite_bytes BIGINT,
    tipo_arquivos_bloqueados INT,
    enviar_notificacao BOOLEAN
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS auditoria_regras (
    id_registro_auditoria_regras INT PRIMARY KEY,
    fk_id_regras INT,
    fk_id_usuario_autor INT,
    bloquear_senhas_antigo BOOLEAN,
    bloquear_tokens_antigo BOOLEAN,
    bloquear_cpf_antigo BOOLEAN,
    bloquear_numero_cartao_antigo BOOLEAN,
    timeout_antigo INT,
    tamanho_limite_bytes_antigo BIGINT,
    tipo_arquivos_bloqueados_antigo INT,
    enviar_notificacao_antigo BOOLEAN,
    bloquear_senhas_novo BOOLEAN,
    bloquear_tokens_novo BOOLEAN,
    bloquear_cpf_novo BOOLEAN,
    bloquear_numero_cartao_novo BOOLEAN,
    timeout_novo INT,
    tamanho_limite_bytes_novo BIGINT,
    tipo_arquivos_bloqueados_novo INT,
    enviar_notificacao_novo BOOLEAN,
    data_hora_modificacao DATETIME,
    CONSTRAINT fk_id_regras_01 FOREIGN KEY (fk_id_regras) REFERENCES regras (id_regras)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_usuario_02 FOREIGN KEY (fk_id_usuario_autor) REFERENCES acesso.usuarios (id_usuario)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS agentes_transmissores (
    id_agente_transmissor INT PRIMARY KEY,
    nome_agente VARCHAR(30) NOT NULL,
    tipo VARCHAR(20)
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS politicas (
    id_politica INT PRIMARY KEY,
    fk_id_usuario_so INT,
    fk_id_regras INT,
    fk_id_agente_transmissor INT,
    CONSTRAINT fk_id_usuario_so_02 FOREIGN KEY (fk_id_usuario_so) REFERENCES usuarios_so (id_usuario_so)
    ON DELETE CASCADE,
    CONSTRAINT fk_id_regras_02 FOREIGN KEY (fk_id_regras) REFERENCES regras (id_regras)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_agente_transmissor_01 FOREIGN KEY (fk_id_agente_transmissor) REFERENCES agentes_transmissores (id_agente_transmissor)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS eventos (
    id_evento INT PRIMARY KEY,
    fk_id_usuario_so INT,
    fk_id_objeto INT,
    fk_id_agente_transmissor INT,
    fk_id_politica INT,
    veredito INT,
    motivo VARCHAR(1000),
    inicio_execucao DATETIME,
    termino_execucao DATETIME,
    CONSTRAINT fk_id_usuario_so_03 FOREIGN KEY (fk_id_usuario_so) REFERENCES usuarios_so (id_usuario_so)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_objeto_01 FOREIGN KEY (fk_id_objeto) REFERENCES objetos (id_objeto)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_agente_transmissor_02 FOREIGN KEY (fk_id_agente_transmissor) REFERENCES agentes_transmissores (id_agente_transmissor)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_politica_01 FOREIGN KEY (fk_id_politica) REFERENCES politicas (id_politica)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS solicitacoes (
    id_solicitacao INT PRIMARY KEY,
    fk_id_usuario_so INT,
    fk_id_objeto INT,
    fk_id_agente_transmissor INT,
    fk_id_empresa_designada INT,
    fk_id_admin_designado INT,
    descricao VARCHAR(1000),
    situacao INT,
    data_hora DATETIME,
    CONSTRAINT fk_id_usuario_so_04 FOREIGN KEY (fk_id_usuario_so) REFERENCES usuarios_so (id_usuario_so)
    ON DELETE CASCADE,
    CONSTRAINT fk_id_objeto_02 FOREIGN KEY (fk_id_objeto) REFERENCES objetos (id_objeto)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_agente_transmissor_03 FOREIGN KEY (fk_id_agente_transmissor) REFERENCES agentes_transmissores (id_agente_transmissor)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_empresa_02 FOREIGN KEY (fk_id_empresa_designada) REFERENCES acesso.empresas (id_empresa)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_usuario_03 FOREIGN KEY (fk_id_admin_designado) REFERENCES acesso.usuarios (id_usuario)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS auditoria_politicas (
    id_registro_auditoria_politicas INT PRIMARY KEY,
    fk_id_usuario_autor INT,
    fk_id_politica_alterada INT,
    fk_id_usuario_so_antigo INT,
    fk_id_regras_antigo INT,
    fk_id_agente_transmissor_antigo INT,
    fk_id_usuario_so_novo INT,
    fk_id_regras_novo INT,
    fk_id_agente_transmissor_novo INT,
    data_alteracao DATETIME,
    CONSTRAINT fk_id_usuario_04 FOREIGN KEY (fk_id_usuario_autor) REFERENCES acesso.usuarios (id_usuario)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_politica_02 FOREIGN KEY (fk_id_politica_alterada) REFERENCES politicas (id_politica)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_usuario_so_05 FOREIGN KEY (fk_id_usuario_so_antigo) REFERENCES usuarios_so (id_usuario_so)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_regras_03 FOREIGN KEY (fk_id_regras_antigo) REFERENCES regras (id_regras)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_agente_transmissor_04 FOREIGN KEY (fk_id_agente_transmissor_antigo) REFERENCES agentes_transmissores (id_agente_transmissor)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_usuario_so_06 FOREIGN KEY (fk_id_usuario_so_novo) REFERENCES usuarios_so (id_usuario_so)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_regras_04 FOREIGN KEY (fk_id_regras_novo) REFERENCES regras (id_regras)
    ON DELETE SET NULL,
    CONSTRAINT fk_id_agente_transmissor_05 FOREIGN KEY (fk_id_agente_transmissor_novo) REFERENCES agentes_transmissores (id_agente_transmissor)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;