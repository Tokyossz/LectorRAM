# Forensic Memory Analyzer PRO v1.5

Herramienta en C++ para el análisis forense de memoria virtual en procesos de Windows. Permite la extracción de cadenas ASCII y UTF-16 mediante escaneo multihilo.

## Requisitos para el funcionamiento

Para que el programa funcione correctamente, es **obligatorio** cumplir con los siguientes puntos:

1.  **Privilegios de Administrador:** El ejecutable debe ejecutarse con permisos elevados para poder abrir y leer la memoria de otros procesos del sistema.
2.  **Arquitectura x64:** El proyecto debe compilarse y ejecutarse estrictamente en configuración **x64**. No es compatible con x86 debido al manejo de direcciones de memoria de 64 bits.
3.  **Configuración de Caracteres Unicode:** En las propiedades del proyecto de Visual Studio, el Juego de Caracteres debe estar configurado como **"Utilizar juego de caracteres Unicode"**.
4.  **Windows API:** Requiere las librerías de Windows (`windows.h`, `psapi.lib`) incluidas en el SDK de Windows 10/11.

## Guía de uso rápido

1. Abrir `LectorRAM.slnx` o `LectorRAM.vcxproj` en Visual Studio 2022.
2. Seleccionar la configuración **Release** o **Debug** en plataforma **x64**.
3. Compilar la solución.
4. Ejecutar el programa como administrador.
5. Introducir el índice del proceso, filtros de búsqueda (opcional) y el nombre del archivo para generar el reporte forense.
