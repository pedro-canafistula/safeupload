# 🛡️ SafeUpload Endpoint Agent

Interface desktop de monitoramento de endpoint, feita em **WPF (C#)**.

---

## 🧱 Tecnologia

Este projeto usa **WPF (Windows Presentation Foundation)**, o framework da
Microsoft para criar interfaces gráficas de desktop no Windows, usando **C#**
para a lógica e **XAML** para o design das telas.

- **.NET 8**
- **C#**
- **XAML** (linguagem de marcação da interface)

> ⚠️ Só roda no **Windows** — WPF não existe para Linux/macOS.

---

## ▶️ Como rodar

### 1. Instale o .NET 8 SDK

**Opção A — Instalador (site oficial)**

Baixe aqui: https://dotnet.microsoft.com/pt-br/download/dotnet/8.0

**Opção B — Via terminal (winget)**

```bash
winget install Microsoft.DotNet.SDK.8
```

> Depois de instalar, feche e abra o terminal novamente para que o comando
> `dotnet` seja reconhecido.

Confirme a instalação no terminal:

```bash
dotnet --version
```

### 2. Abra o terminal na pasta do projeto

```bash
cd SafeUploadAgent
```

### 3. Rode o projeto

```bash
dotnet restore
dotnet build
dotnet run
```

A janela do **SafeUpload Endpoint Agent** vai abrir automaticamente. 🎉

---

## 📁 Estrutura

```
SafeUploadAgent/
├── App.xaml            # Ponto de entrada da aplicação
├── App.xaml.cs
├── MainWindow.xaml      # Tela principal (layout e design)
├── MainWindow.xaml.cs   # Lógica da tela
└── SafeUploadAgent.csproj
```

