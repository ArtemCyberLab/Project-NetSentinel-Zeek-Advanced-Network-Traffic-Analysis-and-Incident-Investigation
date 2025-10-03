NetSentinel‑Zeek — Advanced Network Traffic Analysis and Incident Investigation

Project Objective:
In this project, I conducted a full-scale investigation of network incidents on the target host 10.201.79.109. The main task was to leverage Zeek to identify anomalies, phishing attacks, and exploitation attempts, followed by artifact extraction, alert validation, and drawing conclusions about network security.
This project demonstrates how a systematic approach to network traffic analysis using Zeek enables fast and accurate threat detection, artifact collection, and formulation of actionable recommendations to improve cybersecurity posture.

Project Description (First-Person Perspective):
My goal was to simulate a real-world corporate infrastructure scenario requiring detection and analysis of complex network threats. Working with Zeek allowed me to thoroughly examine PCAP files of the target host’s traffic, including DNS, HTTP, file, and signature logs. I built data processing pipelines that automatically filtered noise, detected repeated requests, identified unique domains, and analyzed the activity of suspicious hosts.

What Was Implemented:

DNS Tunneling: I detected mass activity related to AAAA records and determined the IP address of the traffic initiator. This allowed me to confirm that the signature alerts were true positives and assess the potential risk of data exfiltration.

Phishing Attacks: By analyzing HTTP traffic and file logs, I identified the source address distributing malicious content and extracted artifacts, including a VBA document and an executable file (PleaseWaitWindow.exe), as well as the command-and-control domain. All suspicious elements were verified via VirusTotal.

Log4J Exploitation: Using custom scripts to detect Log4Shell attempts, I confirmed multiple signature hits, identified scanning tools, extracted extensions of uploaded exploits, and decoded Base64 commands to uncover created files (pwned).

Conclusions:
The analysis revealed that the target host 10.201.79.109 was subjected to multiple threats: DNS tunneling, phishing, and Log4J exploitation attempts. All detected activities were confirmed with artifacts and showed characteristics of real attacks. The project not only validated the alerts but also allowed me to develop practical recommendations for host isolation, monitoring suspicious domains, and implementing protections against Log4J exploits.

Practical Value of the Project:

Demonstrates a full process of network traffic analysis using Zeek.

Enables reproducible threat detection and artifact extraction.

Develops pipelines for filtering, aggregating, and identifying anomalous patterns.

Provides actionable recommendations for incident response and risk mitigation.

**************************************************************************************************************************************************************************************************************

NetSentinel‑Zeek — Análise Avançada de Tráfego de Rede e Investigação de Incidentes

Objetivo do Projeto:
Neste projeto, realizei uma investigação completa de incidentes de rede no host alvo 10.201.79.109. A principal tarefa foi utilizar o Zeek para identificar anomalias, ataques de phishing e tentativas de exploração de vulnerabilidades, seguida da extração de artefatos, validação de alertas e formulação de conclusões sobre a segurança da rede.
Este projeto demonstra como uma abordagem sistemática de análise de tráfego de rede com Zeek permite detectar ameaças de forma rápida e precisa, coletar artefatos e gerar recomendações acionáveis para aprimorar a postura de cibersegurança.

Descrição do Projeto (Perspectiva Pessoal):
Meu objetivo foi simular um cenário de infraestrutura corporativa real, onde é necessário detectar e analisar ameaças de rede complexas. Trabalhar com Zeek me permitiu examinar detalhadamente arquivos PCAP do tráfego do host alvo, incluindo logs de DNS, HTTP, arquivos e assinaturas. Criei pipelines de processamento de dados que filtram automaticamente ruídos, detectam requisições repetidas, identificam domínios únicos e analisam a atividade de hosts suspeitos.

O Que Foi Implementado:

Túnel DNS: Detectei atividade massiva relacionada a registros AAAA e determinei o endereço IP do iniciador do tráfego. Isso permitiu confirmar que os alertas das assinaturas eram verdadeiros positivos e avaliar o risco potencial de exfiltração de dados.

Ataques de Phishing: Ao analisar o tráfego HTTP e logs de arquivos, identifiquei o endereço de origem que distribuía conteúdo malicioso e extraí artefatos, incluindo um documento VBA e um executável (PleaseWaitWindow.exe), além do domínio de comando e controle. Todos os elementos suspeitos foram verificados via VirusTotal.

Exploração do Log4J: Utilizando scripts personalizados para detectar tentativas de Log4Shell, confirmei múltiplos alertas, identifiquei ferramentas de varredura, extraí extensões de exploits carregados e decodifiquei comandos em Base64 para identificar arquivos criados (pwned).

Conclusões:
A análise mostrou que o host alvo 10.201.79.109 sofreu múltiplas ameaças: túnel DNS, phishing e tentativas de exploração do Log4J. Todas as atividades detectadas foram confirmadas com artefatos e apresentaram características de ataques reais. O projeto não apenas validou os alertas, mas também permitiu desenvolver recomendações práticas para isolamento do host, monitoramento de domínios suspeitos e implementação de proteções contra exploits do Log4J.

Valor Prático do Projeto:

Demonstra o processo completo de análise de tráfego de rede com Zeek.

Permite a detecção de ameaças e extração de artefatos de forma reproduzível.

Desenvolve pipelines para filtragem, agregação e identificação de padrões anômalos.

Fornece recomendações acionáveis para resposta a incidentes e mitigação de riscos.
