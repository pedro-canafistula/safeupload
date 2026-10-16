CREATE DATABASE IF NOT EXISTS acesso;

USE acesso;

CREATE TABLE IF NOT EXISTS enderecos (
    id_endereco INT PRIMARY KEY AUTO_INCREMENT,
    cep VARCHAR(9),
    logradouro VARCHAR(40),
    numero INT,
    complemento VARCHAR(100),
    bairro VARCHAR(30),
    cidade VARCHAR(40),
    estado CHAR(2)
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS empresas (
    id_empresa INT PRIMARY KEY AUTO_INCREMENT,
    razao_social VARCHAR(100) UNIQUE,
    nome_fantasia VARCHAR (100),
    cnpj VARCHAR(14),
    email_contato VARCHAR(100),
    telefone_contato VARCHAR(14),
    fk_id_endereco INT,
    CONSTRAINT fk_id_endereco_01 FOREIGN KEY (fk_id_endereco) REFERENCES enderecos (id_endereco)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS usuarios (
    id_usuario INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(75) NOT NULL UNIQUE,
    cpf VARCHAR(14) NOT NULL UNIQUE,
    senha VARCHAR(60),
    nome_completo VARCHAR(100) NOT NULL,
    data_nascimento DATE,
    fk_id_empresa INT,
    fk_id_endereco INT,
    bloqueado CHECK(bloqueado BETWEEN 0 AND 1),
    role VARCHAR (20),
    criado_por VARCHAR(50),
    data_cadastro TIMESTAMP,
    CONSTRAINT fk_id_empresa_01 FOREIGN KEY (fk_id_empresa) REFERENCES empresas (id_empresa)
    ON DELETE CASCADE,
    CONSTRAINT fk_id_endereco_02 FOREIGN KEY (fk_id_endereco) REFERENCES enderecos (id_endereco)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sessoes (
    id_sessao INT PRIMARY KEY AUTO_INCREMENT,
    fk_id_usuario INT,
    ip_origem VARCHAR(15),
    tentativa_conexao INT,
    motivo VARCHAR(200),
    status INT,
    data_hora_logon TIMESTAMP,
    data_hora_logoff TIMESTAMP,
    CONSTRAINT fk_id_usuario_01 FOREIGN KEY (fk_id_usuario) REFERENCES usuarios (id_usuario)
    ON DELETE SET NULL
) ENGINE=InnoDB
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;