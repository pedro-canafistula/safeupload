package com.safeupload.application;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safeupload.application.dto.Politica;
import com.safeupload.domain.entity.PoliticaEntity;
import com.safeupload.infrastructure.repository.PoliticaRepository;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class PoliticaService {
    private final PoliticaRepository repository;
    private final ObjectMapper mapper;

    public PoliticaService(PoliticaRepository repository, ObjectMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Transactional
    public Politica salvar(Politica politica) {
        repository.findFirstByAtivaTrue().ifPresent(atual -> {
            atual.setAtiva(false);
            repository.save(atual);
        });

        PoliticaEntity entity = new PoliticaEntity(
                politica.justificativa(), json(politica.categoriasMonitoradas()), json(politica.extensoesMonitoradas()),
                json(listaOuVazia(politica.caminhosDeDestino())), politica.monitorarUnidadesRemoviveis(),
                politica.monitorarCaminhosDeRede(), politica.tamanhoMaximoArquivoMb(),
                politica.tempoLimiteInspecaoSegundos(), politica.somenteAuditoria(), politica.permitirExcecao(),
                politica.permitirEmCasoDeFalha(), json(listaOuVazia(politica.processosIgnorados())));
        return paraDto(repository.save(entity));
    }

    @Transactional(readOnly = true)
    public Politica buscarAtiva() {
        return repository.findFirstByAtivaTrue()
                .map(this::paraDto)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Nenhuma política ativa foi configurada."));
    }

    private Politica paraDto(PoliticaEntity entity) {
        return new Politica(entity.getJustificativa(), categorias(entity.getCategoriasMonitoradas()),
                strings(entity.getExtensoesMonitoradas()), strings(entity.getCaminhosDeDestino()),
                entity.isMonitorarUnidadesRemoviveis(), entity.isMonitorarCaminhosDeRede(),
                entity.getTamanhoMaximoArquivoMb(), entity.getTempoLimiteInspecaoSegundos(),
                entity.isSomenteAuditoria(), entity.isPermitirExcecao(), entity.isPermitirEmCasoDeFalha(),
                strings(entity.getProcessosIgnorados()));
    }

    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (Exception exception) { throw new IllegalStateException("Não foi possível serializar a política.", exception); }
    }

    private List<Politica.CategoriaMonitorada> categorias(String value) {
        try { return mapper.readValue(value, new TypeReference<>() { }); }
        catch (Exception exception) { throw new IllegalStateException("Categorias armazenadas são inválidas.", exception); }
    }

    private List<String> strings(String value) {
        try { return mapper.readValue(value, new TypeReference<>() { }); }
        catch (Exception exception) { throw new IllegalStateException("Lista armazenada é inválida.", exception); }
    }

    private static List<String> listaOuVazia(List<String> lista) { return lista == null ? List.of() : lista; }
}
