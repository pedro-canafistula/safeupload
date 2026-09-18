CREATE DATABASE IF NOT EXISTS acesso;

USE acesso;

CREATE TABLE IF NOT EXISTS enderecos (
    id_endereco INT PRIMARY KEY,
    cep VARCHAR(10),
    logradouro VARCHAR(40),
    numero INT,
    complemento VARCHAR(40),
    bairro VARCHAR(30),
    cidade VARCHAR(40),
    estado CHAR(2)
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS empresas (
    id_empresa INT PRIMARY KEY,
    razao_social VARCHAR(100),
    nome_fantasia VARCHAR (100),
    cnpj VARCHAR(14),
    email_contato VARCHAR(75),
    telefone_contato VARCHAR(14),
    fk_id_endereco INT,
    CONSTRAINT fk_id_endereco_01 FOREIGN KEY (fk_id_endereco) REFERENCES enderecos (id_endereco)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS usuarios (
    id_usuario INT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(75) NOT NULL,
    cpf VARCHAR(14) NOT NULL,
    senha VARCHAR(30),
    nome_completo VARCHAR(100) NOT NULL,
    data_nascimento DATE,
    fk_id_empresa INT,
    fk_id_endereco INT,
    bloqueado BOOLEAN,
    role VARCHAR (20),
    data_cadastro DATETIME,
    CONSTRAINT fk_id_empresa_01 FOREIGN KEY (fk_id_empresa) REFERENCES empresas (id_empresa)
    ON DELETE CASCADE,
    CONSTRAINT fk_id_endereco_02 FOREIGN KEY (fk_id_endereco) REFERENCES enderecos (id_endereco)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sessoes (
    id_sessao INT PRIMARY KEY,
    fk_id_usuario INT,
    ip_origem VARCHAR(15),
    agente_conexao VARCHAR(30),
    tentativa_conexao BOOLEAN,
    motivo VARCHAR(200),
    status BOOLEAN,
    data_hora_logon DATETIME,
    data_hora_logout DATETIME,
    CONSTRAINT fk_id_usuario_01 FOREIGN KEY (fk_id_usuario) REFERENCES usuarios (id_usuario)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;