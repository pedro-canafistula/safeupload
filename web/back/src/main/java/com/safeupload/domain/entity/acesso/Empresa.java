package com.safeupload.domain.entity.acesso;

import jakarta.persistence.*;

@Entity 
@Table (name="empresas")
public class Empresa {
    @Id 
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    @Column (name="id_empresa")
    private Integer idEmpresa;

    @Column (name="razao_social")
    private String razaoSocial;

    @Column (name="nome_fantasia")
    private String nomeFantasia;

    @Column (name="cnpj")
    private String cnpj;

    @Column (name="email_contato")
    private String emailContato;

    @Column (name="telefone_contato")
    private String telefoneContato;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(
        name="fk_id_endereco",
        nullable=true,
        foreignKey = @ForeignKey (name = "fk_id_endereco_01")
    )
    private Endereco fkIdEndereco;

    protected Empresa(){}

    public Empresa(
        String razaoSocial,
        String nomeFantasia,
        String cnpj,
        String emailContato,
        String telefoneContato,
        Endereco fkIdEndereco
    ){
        this.razaoSocial = razaoSocial;
        this.nomeFantasia = nomeFantasia;
        this.cnpj = cnpj;
        this.emailContato = emailContato;
        this.telefoneContato = telefoneContato;
        this.fkIdEndereco = fkIdEndereco;
    }

    public Integer getIdEmpresa (){
        return idEmpresa;
    }

    public String getRazaoSocial (){
        return razaoSocial;
    }

    public String getNomeFantasia(){
        return nomeFantasia;
    }

    public String getCnpj(){
        return cnpj;
    }

    public String getEmailContato(){
        return emailContato;
    }

    public String getTelefoneContato(){
        return telefoneContato;
    }

    public Endereco getFkIdEndereco(){
        return fkIdEndereco;
    }

}
