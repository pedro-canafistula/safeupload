using System.Windows;

namespace SafeUpload.Agent.App;

/// <summary>
/// Ponto de entrada e "composition root" do agente.
/// A composicao concreta (bandeja, janelas, servico de inspecao) e montada
/// na etapa da interface; por ora a aplicacao apenas sobe sem janela.
/// </summary>
public partial class App : Application
{
}
