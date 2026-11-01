package com.safeupload.domain.entity.acesso;

import java.time.LocalDate;
import java.time.LocalDateTime;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import jakarta.persistence.*;

@Entity 
@Table (name="usuarios")
public class Usuario {
    @Id 
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    @Column (name="id_usuario")
    private Integer idUsuario;

    @Column (name="username")
    private String username;

    @Column (name="email")
    private String email;

    @Column (name="cpf")
    private String cpf;

    @Column (name="senha")
    private String senha;

    @Column (name="nome_completo")
    private String nomeCompleto;

    @Column (name="data_nascimento")
    private LocalDate dataNascimento;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn (
        name="fk_id_empresa",
        nullable=false,
        foreignKey = @ForeignKey (name = "fk_id_empresa_01")
    )
    @OnDelete (action = OnDeleteAction.CASCADE)
    private Empresa fkIdEmpresa;

    @OneToOne (fetch = FetchType.LAZY)
    @JoinColumn (
        name="fk_id_endereco",
        nullable=true,
        foreignKey = @ForeignKey (name = "fk_id_endereco")
    )
    private Endereco fkIdEndereco;

    @Column(name="bloqueado")
    private int bloqueado;

    @Column (name="role")
    private String role;

    @Column (name="criado_por")
    private String criadoPor;

    @Column (name="data_cadastro")
    private LocalDateTime dataCadastro;

    protected Usuario(){}

    public Usuario(
        String username,
        String email,
        String cpf,
        String senha,
        String nomeCompleto,
        LocalDate dataNascimento,
        Empresa fkIdEmpresa,
        Endereco fkIdEndereco,
        int bloqueado,
        String role,
        String criadoPor,
        LocalDateTime dataCadastro
    ){
        this.username = username;
        this.email = email;
        this.cpf = cpf;
        this.senha = senha;
        this.nomeCompleto = nomeCompleto;
        this.dataNascimento = dataNascimento;
        this.fkIdEmpresa = fkIdEmpresa;
        this.fkIdEndereco = fkIdEndereco;
        this.bloqueado = bloqueado;
        this.role = role;
        this.criadoPor = criadoPor;
        this.dataCadastro = dataCadastro;
    }

    public Integer getIdUsuario (){
        return idUsuario;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getCpf() {
        return cpf;
    }

    public String getSenha() {
        return senha;
    }

    public String getNomeCompleto() {
        return nomeCompleto;
    }

    public LocalDate getDataNascimento() {
        return dataNascimento;
    }

    public Empresa getFkIdEmpresa() {
        return fkIdEmpresa;
    }

    public Endereco getFkIdEndereco() {
        return fkIdEndereco;
    }

    public int getBloqueado() {
        return bloqueado;
    }

    public String getRole() {
        return role;
    }

    public String getCriadoPor(){
        return criadoPor;
    }

    public LocalDateTime getDataCadastro() {
        return dataCadastro;
    }
}
