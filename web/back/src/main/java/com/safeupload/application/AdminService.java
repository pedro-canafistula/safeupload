package com.safeupload.application;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.safeupload.application.dto.AdminContracts.DefaultPostResponse;
import com.safeupload.application.dto.AdminContracts.SetPolicyRequest;
import com.safeupload.domain.entity.app.Host;
import com.safeupload.domain.entity.app.Politica;
import com.safeupload.domain.entity.app.Regras;
import com.safeupload.infrastructure.repository.app.HostRepository;
import com.safeupload.infrastructure.repository.app.PoliticaRepository;
import com.safeupload.infrastructure.repository.app.RegrasRepository;
import com.safeupload.presentation.exception.DatabaseErrorException;



@Service 
public class AdminService {
    private final PoliticaRepository politicaRepository;
    private final RegrasRepository regrasRepository;
    private final HostRepository hostRepository;
    private final RestClient restClient;

    public AdminService (
        PoliticaRepository politicaRepository,
        RegrasRepository regrasRepository,
        HostRepository hostRepository,
        RestClient restClient
    ){
        this.politicaRepository = politicaRepository;
        this.regrasRepository = regrasRepository;
        this.hostRepository = hostRepository;
        this.restClient = restClient;
    }

    public DefaultPostResponse setPolicy(SetPolicyRequest request){

        Regras regras = convertRules(request.regras());

        regras = regrasRepository.save(regras);

        Host host = hostRepository.findByIp(request.destino().ip())
            .orElseThrow(() ->
            new DatabaseErrorException(
                "Nenhum host cadastrado com o IP: " + request.destino().ip()
            )
        );

        LocalDateTime criadaEm = request.criadaEm() == null
            ? null
            : request.criadaEm()
                .atZoneSameInstant(ZoneId.of("America/Sao_Paulo"))
                .toLocalDateTime();

        Politica politica = new Politica (
            request.versao(),
            request.nome(),
            host,
            request.acao(),
            regras,
            criadaEm,
            request.origem() 
        );

        politica = politicaRepository.save(politica);

        return new DefaultPostResponse(
            HttpStatus.CREATED, 
            "Política salva com sucesso."
        );
    }


    private Regras convertRules(List<SetPolicyRequest.RegraRequest> regrasDTO) {

        boolean cpf = false;
        boolean cnpj = false;
        boolean rg = false;
        boolean dadosBancarios = false;
        boolean cartaoCredito = false;
        boolean credenciais = false;
        boolean dadosSaude = false;
        boolean dadosPessoais = false;
        boolean documentosConfidenciais = false;

        if (regrasDTO != null) {
            for (SetPolicyRequest.RegraRequest regra : regrasDTO) {

                switch (regra.tipo()) {
                    case "cpf" -> cpf = true;
                    case "cnpj" -> cnpj = true;
                    case "rg" -> rg = true;
                    case "dados_bancarios" -> dadosBancarios = true;
                    case "cartao_credito" -> cartaoCredito = true;
                    case "credenciais" -> credenciais = true;
                    case "dados_saude" -> dadosSaude = true;
                    case "dados_pessoais" -> dadosPessoais = true;
                    case "documentos_confidenciais" ->
                            documentosConfidenciais = true;
                }
            }
        }

        return new Regras(
            cpf ? 1 : 0,
            cnpj ? 1 : 0,
            rg ? 1 : 0,
            dadosBancarios ? 1 : 0,
            cartaoCredito ? 1 : 0,
            credenciais ? 1 : 0,
            dadosSaude ? 1 : 0,
            dadosPessoais ? 1 : 0,
            documentosConfidenciais ? 1 : 0
        );
    }
}
