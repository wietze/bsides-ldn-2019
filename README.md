# The Imitation Game: Attacker Emulation
## BSides London 2019

This repo contains changes made to the [Adversary Plugin](https://github.com/mitre/adversary) repo for CALDERA 2.0.

### Presentation
**Slides**: [HTML](https://wietze.github.io/bsides-ldn-2019/) <img src="https://wietze.github.io/img/html.svg" alt="HTML" width="19"/> and [PDF](https://wietze.github.io/bsides-ldn-2019/slides.pdf) <img src="https://wietze.github.io/img/pdf.svg" alt="PDF" width="19"/>

**Video**: Will be made available later.

## Code changes
Files that were changed include:
* The following steps:
  * [dump_creds](app/steps/dumpcreds.py), a fileless Mimikatz in PowerShell action using `CustomCommandLine` (see below);
  * [certutil_download](app/steps/certutildownload.py), which can download files using the Certutil LOLbin;
  * [rundll32_execution](app/steps/rundll32execution.py), which can execute commands using the RunDLL32/MSHTA LOLbin;
  * [webserver_install](app/steps/webserverinstall.py), which prepares a webserver installation (creates `OPSoftware` object, see below); and,
  * [webshell_execution](app/steps/webshellexecution.py), which uses the above three actions to set up a reverse webshell. 
* [operation.py](app/operation/operation.py), which introduces `OPSoftware`, which is used by some of the above actions (to implement **LOLbins**); and,
* [command.py](app/commands/command.py), which introduces `CustomCommandLine`, which can **obfuscate** commands and apply **masquerading**.  
_Note that this still a proof of concept, as it requires you to supply `drop_file` and `file_g` functions in order to make CALDERA aware of renamed binaries in case of masquerading. See e.g. [dump_creds](app/steps/dumpcreds.py#L54-L60). This should be further optimised._

## Installation
Make sure you have the most recent version of CALDERA (for instructions check the [CALDERA repo](https://github.com/mitre/caldera)).

You can either copy in the files manually to your `caldera/plugins/adversary` folder, or:
1. In the main `caldera/` folder, run the following command: 
   ```bash 
   git config --file=.gitmodules -e
   ```
2. Update the `plugins/adversary` entry, pointing it to `git@github.com:wietze/bsides-ldn-2019.git`  
   (or `git@github.com:wietze/bsides-ldn-2019.git` if you're using SSH)
3. Run the following command to update to the latest version of this repo:
   ```bash
    git submodule sync && git submodule update --remote --merge
   ```

_If you want to return to the original MITRE repository, follow steps 1-3 again, but use `https://github.com/mitre/adversary.git` in step 2._  
_(or `git@github.com:mitre/adversary.git` if you're using SSH)_
