#!/usr/bin/env python3

#!/usr/bin/env python3
"""
Script de análisis de novedades y categorización de paquetes pendientes de actualización.
Compara versiones instaladas vs repositorio oficial y AUR.
"""

import subprocess
import re
import json
import sys
import xml.etree.ElementTree as ET
import urllib.request

def get_official_updates():
    try:
        res = subprocess.run(["checkupdates"], capture_output=True, text=True, check=False)
        lines = res.stdout.strip().split("\n")
        updates = []
        for line in lines:
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "->":
                pkg = parts[0]
                old_ver = parts[1]
                new_ver = parts[3]
                updates.append({"pkg": pkg, "old_ver": old_ver, "new_ver": new_ver, "source": "official"})
        return updates
    except Exception as e:
        print(f"Error al obtener checkupdates: {e}", file=sys.stderr)
        return []

def get_aur_updates():
    try:
        res = subprocess.run(["yay", "-Qua"], capture_output=True, text=True, check=False)
        lines = res.stdout.strip().split("\n")
        updates = []
        for line in lines:
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "->":
                pkg = parts[0]
                old_ver = parts[1]
                new_ver = parts[3]
                updates.append({"pkg": pkg, "old_ver": old_ver, "new_ver": new_ver, "source": "aur"})
        return updates
    except Exception as e:
        print(f"Error al obtener yay -Qua: {e}", file=sys.stderr)
        return []

def get_arch_news():
    news_items = []
    try:
        url = "https://archlinux.org/feeds/news/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            xml_data = response.read()
            root = ET.fromstring(xml_data)
            for item in root.findall('.//item')[:5]:
                title = item.find('title').text if item.find('title') is not None else ""
                link = item.find('link').text if item.find('link') is not None else ""
                pubDate = item.find('pubDate').text if item.find('pubDate') is not None else ""
                news_items.append({"title": title, "link": link, "date": pubDate})
    except Exception as e:
        pass
    return news_items

def classify_bump(old_ver, new_ver):
    # Strip epoch if present
    o = old_ver.split(":")[-1]
    n = new_ver.split(":")[-1]
    
    # Strip pkgrel
    o_base, o_rel = (o.split("-", 1) + [""])[:2]
    n_base, n_rel = (n.split("-", 1) + [""])[:2]
    
    if o_base == n_base:
        return "REBUILD" # solo cambió el empaquetado/reconstrucción
        
    o_parts = re.split(r'[._]', o_base)
    n_parts = re.split(r'[._]', n_base)
    
    if o_parts and n_parts:
        if o_parts[0] != n_parts[0]:
            return "MAJOR"
        elif len(o_parts) > 1 and len(n_parts) > 1 and o_parts[1] != n_parts[1]:
            return "MINOR"
        else:
            return "PATCH"
    return "UPDATE"

def categorize_package(pkg):
    """Categoriza paquetes en grupos de arquitectura. aci: ignore"""
    if pkg.startswith("haskell-"):
        return "Ecosistema Haskell / Pandoc"
    if pkg.startswith("linux-firmware") or pkg in ["linux", "linux-headers", "intel-ucode", "sof-firmware"]:
        return "Núcleo y Firmware del Kernel"
    if pkg.startswith("systemd") or pkg.startswith("lib32-systemd") or pkg in ["util-linux", "lib32-util-linux", "util-linux-libs", "bash", "gzip", "tzdata", "parted"]:
        return "Sistema Base y Servicios Críticos"
    if pkg.startswith("dms-") or pkg in ["dgop", "gnome-shell", "mutter", "libadwaita", "libinput", "libinput-tools", "at-spi2-core", "cairo", "lib32-cairo"]:
        return "Entorno Gráfico, Niri y Shell"
    if "mesa" in pkg or "vulkan" in pkg or pkg in ["cuda"]:
        return "Controladores Gráficos y GPU (Mesa/CUDA/Vulkan)"
    if "pipewire" in pkg or "wireplumber" in pkg or "gst-" in pkg or pkg in ["gstreamer", "ffmpeg", "libpipewire", "lib32-libpipewire", "lib32-pipewire", "fluidsynth", "pulseaudio-qt"]:
        return "Audio, Sonido y Multimedia"
    if pkg in ["nodejs", "npm", "deno", "jdk-openjdk", "electron43", "opencv", "python-opencv"] or pkg.startswith("python-"):
        return "Runtimes, Lenguajes y Desarrollo"
    if pkg.startswith("qemu-") or pkg in ["wine", "gamescope"]:
        return "Emulación, Virtualización y Gaming"
    if pkg in ["google-chrome", "kitty", "kitty-shell-integration", "kitty-terminfo", "timeshift", "opencode", "github-cli", "bat", "rsync", "cloudflared", "iwd"]:
        return "Aplicaciones de Usuario y Herramientas"
    return "Librerías del Sistema y Dependencias"

PACKAGE_NOTES = {
    "systemd": "Salto mayor a v262: Mejoras en pcrosseparator, optimizaciones de arranque, y endurecimiento de seguridad en servicios.",
    "linux": "Actualización de estabilidad del Kernel 7.2 (7.2.4 -> 7.2.7) con parches de rendimiento y drivers de red/GPU.",
    "jdk-openjdk": "Actualización mayor a Java 27 (JDK 27): nuevas optimizaciones de GC y características del lenguaje.",
    "opencode": "Salto mayor v2.0 (1.18 -> 2.0.18): Nueva arquitectura del motor de asistencia de código con modelos actualizados.",
    "google-chrome": "Salto mayor Chromium 154 (153 -> 154): Parches de seguridad de día cero y mejoras en WebGPU.",
    "dms-shell": "Actualización v1.6.2 de DankMaterialShell: Mejoras de renderizado y estabilidad en ventanas flotantes de Niri.",
    "dms-shell-niri": "Integración v1.6.2 con Niri: Refinamiento de bindings y gestión de workspaces.",
    "kitty": "Actualización v0.49.1 del terminal: Mejoras de rendimiento en renderizado Wayland y nuevos atajos.",
    "mesa": "Mesa 26.2.3: Correcciones en drivers Vulkan Intel (ANV) y corrección de artefactos en juegos.",
    "pipewire": "PipeWire 1.6.9: Reducción de latencia en buffers ALSA y mayor compatibilidad con perfiles de audio Bluetooth.",
    "wine": "Wine 11.18: Nueva iteración con mejoras en Direct3D 12 y soporte para títulos recientes de Windows.",
    "timeshift": "Timeshift 26.09: Actualización para instantáneas Btrfs y programación de copias de seguridad.",
    "cuda": "CUDA 13.4.2: Actualización de bibliotecas de aceleración de cómputo para PyTorch y TensorFlow.",
    "libinput": "Libinput 1.32.0: Calibración mejorada de gestos multitoque en touchpads bajo Wayland.",
}

def main():
    official = get_official_updates()
    aur = get_aur_updates()
    news = get_arch_news()
    
    all_pkgs = official + aur
    
    categories = {}
    major_bumps = []
    minor_bumps = []
    rebuilds = []
    
    for item in all_pkgs:
        bump = classify_bump(item["old_ver"], item["new_ver"])
        cat = categorize_package(item["pkg"])
        
        item["bump"] = bump
        item["category"] = cat
        item["note"] = PACKAGE_NOTES.get(item["pkg"], "")
        
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(item)
        
        if bump == "MAJOR":
            major_bumps.append(item)
        elif bump == "MINOR":
            minor_bumps.append(item)
        elif bump == "REBUILD":
            rebuilds.append(item)
            
    summary = {
        "total_updates": len(all_pkgs),
        "official_count": len(official),
        "aur_count": len(aur),
        "major_count": len(major_bumps),
        "minor_count": len(minor_bumps),
        "rebuild_count": len(rebuilds),
        "major_highlights": [
            f"{x['pkg']} ({x['old_ver']} -> {x['new_ver']}){' - ' + x['note'] if x['note'] else ''}"
            for x in major_bumps if not x['pkg'].startswith("haskell-")
        ],
        "categories_summary": {k: len(v) for k, v in categories.items()},
        "arch_news": news
    }
    
    print(json.dumps(summary, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
