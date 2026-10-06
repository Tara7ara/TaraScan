"""Autocompletado para zsh/bash: imprime el script (o: source <(tarascan completion zsh))."""

import argparse

_FLAGS = [
    "-n", "--net", "--map", "-f", "--full", "-r", "--fresh",
    "-y", "--only", "-k", "--skip", "-s", "--sqli", "-b", "--brute",
    "-d", "--deep", "-i", "--ai", "-g", "--guided", "-a", "--auto",
    "-o", "--output",
]


def _subcommands() -> list[tuple[str, str]]:
    from tarascan.commands import help_lines
    return help_lines()


def _gtfobins_bins() -> list[str]:
    from tarascan.commands import gtfobins
    return sorted(k for k in gtfobins._load_db() if not k.startswith("_"))


def _zsh_script() -> str:
    # Las descripciones llevan paréntesis/comas: se pasan por un array y _describe,
    # que las trata como texto libre (no como spec de _alternative).
    describe = " ".join(f"'{name}:{desc}'" for name, desc in _subcommands())
    flags = " ".join(_FLAGS)
    gtfo = " ".join(_gtfobins_bins())
    return f"""#compdef tarascan
# Autocompletado de tarascan para zsh (generado por: tarascan completion zsh)
_tarascan() {{
  local -a _subcmds
  _subcmds=({describe})
  if (( CURRENT == 2 )); then
    _describe -t subcommands 'subcomando' _subcmds
    compadd -- {flags}
    return
  fi
  case "$words[2]" in
    audit)
      (( CURRENT == 3 )) && compadd ssh tls smb ;;
    ws)
      (( CURRENT == 3 )) && compadd init list use
      (( CURRENT == 4 )) && [[ "$words[3]" == use ]] && compadd -- ${{(f)"$(ls ~/audit 2>/dev/null)"}} ;;
    gtfobins)
      compadd {gtfo} ;;
    *)
      compadd -- {flags}
      _files ;;
  esac
}}
compdef _tarascan tarascan
"""


def _bash_script() -> str:
    subs = " ".join(name for name, _ in _subcommands())
    flags = " ".join(_FLAGS)
    gtfo = " ".join(_gtfobins_bins())
    return f"""# Autocompletado de tarascan para bash (generado por: tarascan completion bash)
_tarascan() {{
  local cur prev
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "{subs} {flags}" -- "$cur") )
    return
  fi
  case "${{COMP_WORDS[1]}}" in
    audit)   COMPREPLY=( $(compgen -W "ssh tls smb" -- "$cur") ); return ;;
    ws)      COMPREPLY=( $(compgen -W "init list use $(ls ~/audit 2>/dev/null)" -- "$cur") ); return ;;
    gtfobins) COMPREPLY=( $(compgen -W "{gtfo}" -- "$cur") ); return ;;
  esac
  COMPREPLY=( $(compgen -W "{flags}" -- "$cur") )
}}
complete -F _tarascan tarascan
"""


def cmd_completion(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan completion", description="imprime el script de autocompletado (zsh/bash)")
    p.add_argument("shell", nargs="?", choices=["zsh", "bash"], default="zsh", help="shell (por defecto zsh)")
    args = p.parse_args(argv)

    # Salida CRUDA (para redirigir a un fichero o 'source'): sin paneles ni color.
    script = _zsh_script() if args.shell == "zsh" else _bash_script()
    print(script, end="")
    return 0
