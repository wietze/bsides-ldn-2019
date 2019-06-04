# The Imitation Game: Attacker Emulation
## BSides London 2019

This repo contains changes made to the [Adversary Plugin](https://github.com/mitre/adversary) repo for CALDERA 2.0.

### Presentation
**Slides**: [HTML](https://wietze.github.io/bsides-ldn-2019/) and [PDF](https://wietze.github.io/bsides-ldn-2019/slides.pdf)

**Video**: Will be made available later.

## Code changes
Files that were changed include:
* The actions [dump_creds](app/steps/dumpcreds.py), [certutil_download](app/steps/certutildownload.py), [rundll32_execution](app/steps/rundll32execution.py), [webserver_install](app/steps/webserverinstall.py) and [webshell_execution](app/steps/webshellexecution.py);
* [operation.py](app/operation/operation.py), which introduces `OPSoftware`, which is used by some of the above actions (to implement *LOLbins*); and
* [command.py](app/commands/command.py), which introduces `CustomCommandLine`, which can *obfuscate* commands and apply *masquerading*.  
_Note that this still a proof of concept, as it requires you to supply `drop_file` and `file_g` functions in order to make CALDERA aware of renamed binaries in case of masquerading. See e.g. [dump_creds](app/steps/dumpcreds.py#L54-L60). This should be further optimised._
