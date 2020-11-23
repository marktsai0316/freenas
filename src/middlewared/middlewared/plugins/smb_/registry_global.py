from middlewared.service import private, Service
from middlewared.service_exception import CallError
from middlewared.utils import run
from middlewared.plugins.smb import SMBCmd, SMBPath, LOGLEVEL_MAP
from middlewared.plugins.activedirectory import DEFAULT_AD_PARAMETERS
from middlewared.utils import osc

DEFAULT_GLOBAL_PARAMETERS = {
    "dns proxy": "No",
    "max log size": "51200",
    "load printers": "No",
    "printing": "bsd",
    "printcap": "/dev/null",
    "disable spoolss": "Yes",
    "dos filemode": "yes",
    "kernel change notify": "No" if osc.IS_FREEBSD else "Yes",
    "directory name cache size": "0" if osc.IS_FREEBSD else "100",
    "enable web service discovery": "Yes",
    "bind interfaces only": "Yes",
    "registry": "Yes",
    "registry shares": "Yes"
}

DEFAULT_LDAP_PARAMETERS = {
    "server role": "member server",
    "security": "user",
    "ldap replication sleep": "1000",
    "ldap passwd sync": "Yes",
    "ldapsam trusted": "Yes",
    "passdb backend": None,
    "ldap admin dn": None,
    "ldap suffix": None,
    "ldap ssl": None,
}


class SMBService(Service):

    class Config:
        service = 'cifs'
        service_verb = 'restart'

    @private
    async def reg_default_params(self):
        ret = {}
        ret['smb'] = default_global_parameters.keys()
        ret['ad'] = DEFAULT_AD_PARAMETERS.keys()
        ret['ldap'] = default_ldap_parameters.keys()
        return ret

    @private
    async def strip_idmap(self, reg_defaults):
        """
        All params related to idmap backends will be handled
        in idmap plugin.
        """
        idmap_params = {}
        for k, v in reg_defaults.items():
            if k.startswith("idmap config"):
                idmap_params[k] = v

        for e in idmap_params.keys():
            reg_defaults.pop(e, "")

        return idmap_params

    @private
    async def strip_directory_services(self, reg_defaults):
        def_ds_params = []
        def_ds_params.extend(default_ad_parameters.keys())
        def_ds_params.extend(default_ldap_parameters.keys())
        ds_params = {}

        for k, v in reg_defaults.items():
            if k in def_ds_params:
                ds_params[k] = v

        for e in ds_params.keys():
            reg_defaults.pop(e, "")

        return ds_params

    @private
    async def reg_globals(self):
        """
        Split smb.conf parameters into portions used by relevant plugins.
        """
        ret = {}
        global_conf = await self.middleware.call('sharing.smb.reg_showshare', 'global')
        ret['raw'] = global_conf.copy()
        ret['idmap'] = await self.strip_idmap(global_conf)
        ret['ds'] = await self.strip_directory_services(global_conf)
        ret['smb'] = global_conf
        return ret

    @private
    async def strip_defaults(self, reg_defaults):
        def remove_keys(to_remove):
            self.logger.debug(to_remove)
            to_delete = []
            for k, v in to_remove.items():
                if reg_defaults.get(k) == v:
                    to_delete.append(k)
            for e in to_delete:
                reg_defaults.pop(e, "")

        server_role = reg_defaults.pop("server role", "standalone")
        security = reg_defaults.pop("security", "")
        ad_enabled = security == "ADS"
        ldap_enabled = server_role == "member server" and security == "user"

        remove_keys(default_global_parameters.copy())
        if ad_enabled:
            remove_keys(default_ad_parameters)
            reg_defaults.pop('realm')
            reg_defaults.pop('template homedir')
            reg_defaults.pop('ads dns update')
            reg_defaults.pop('allow trusted domains')
            reg_defaults.pop('winbind use default domain')
            reg_defaults.pop('winbind nss info')
            reg_defaults.pop('winbind enum users')
            reg_defaults.pop('winbind enum groups')

        if ldap_enabled:
            remove_keys(default_ldap_parameters)
            reg_defaults.pop("obey pam restrictions")
            reg_defaults.pop("passdb backend")
            reg_defaults.pop("ldap ssl")
            reg_defaults.pop("ldap admin dn")
            reg_defaults.pop("ldap suffix")

    @private
    async def reg_config(self):
        """
        Convert registry config back into our normal smb.conf fields.
        Parametric entries in smb.conf bypass validation. This means
        that TrueNAS-config specific parameters can be safely written
        with a "tn:" prefix.
        """
        reg_globals = (await self.middleware.call('smb.reg_globals'))['smb']
        bind_ips = (reg_globals.pop("interfaces", "")).split()
        if bind_ips:
            bind_ips.remove("127.0.0.1")

        reg_globals.pop("bind interfaces only", "")
        loglevel = reg_globals.pop("log level", "1")
        if loglevel.startswith("syslog@"):
            loglevel = loglevel[len("syslog@")]

        llevel = LOGLEVEL_MAP.get(loglevel.split()[0])

        ret = {
            "id": 1,
            "netbiosname": reg_globals.pop("tn:netbiosname"),
            "netbiosname_b": reg_globals.pop("tn:netbiosname_b"),
            "netbiosname_local": reg_globals.pop("netbios name", ""),
            "workgroup": reg_globals.pop("workgorup", "WORKGROUP"),
            "cifs_SID": reg_globals.pop("tn:sid", None),
            "netbiosalias": (reg_globals.pop("netbios aliases", "")).split(),
            "description": reg_globals.pop("server string"),
            "enable_smb1": reg_globals.pop("server min protocol", "SMB2_10") == "NT1",
            "unixcharset": reg_globals.pop("unix charset", "UTF8"),
            "syslog": reg_globals.pop("syslog only", "No") == "Yes",
            "aapl_extensions": reg_globals.pop("tn:fruit_enabled", "No") == "Yes",
            "localmaster": False,
            "loglevel": llevel,
            "guest": reg_globals.pop("guest account", "nobody"),
            "admin_group": reg_globals.pop("tn:admin_group", ""),
            "filemask": reg_globals.pop("create mask", "0775"),
            "dirmask": reg_globals.pop("directory mask", "0775"),
            "ntlmv1_auth": reg_globals.pop("ntlm auth", "No") == "Yes",
            "bind ip": bind_ips,
        }
        reg_globals.pop('logging')
        aux_list = [f"{k} = {v}" for k, v in reg_globals.items()]
        ret['smb_options'] = aux_list
        return ret

    @private
    async def global_setparm(self, parameter, value):
        cmd = await run([SMBCmd.NET.value, 'conf', 'setparm', 'global', parameter, value], check=False)
        if cmd.returncode != 0:
            raise CallError(f"Failed to set parameter [{parameter}] to [{value}]: "
                            f"{cmd.stderr.decode().strip()}")

    @private
    async def global_parm(self, parameter):
        cmd = await run([SMBCmd.NET.value, 'conf', 'delparm', 'global', parameter], check=False)
        if cmd.returncode != 0:
            raise CallError(f"Failed to delete parameter [{parameter}]: "
                            f"{cmd.stderr.decode().strip()}")

    @private
    async def reg_apply_conf_diff(self, diff):
        to_set = diff.get('added', {})
        to_delete = diff.get('removed', {})
        to_set.update({diff.get('modified', {})})

        for k, v in to_set.items():
            await self.global_setparm(k, v)

        for k in to_delete.keys():
            await self.global_delparm(k)

    @private
    async def reg_update(self, data):
        diff = await self.diff_conf_and_registry(data, False)
        await self.reg_apply_conf_diff(diff)

    @private
    async def get_smb_homedir(self, gen_params):
        homedir = "/home"
        if "HOMES" in gen_params['shares']:
            homedir = (await self.middleware.call("sharing.smb.reg_showshare", "HOMES"))['path']
        return homedir

    @private
    async def pam_is_required(self, gen_params):
        """
        obey pam restictions parameter is requried to allow pam_mkhomedir to operate on share connect.
        It is also required to enable kerberos auth in LDAP environments
        """
        if "HOMES" in gen_params['shares']:
            return True
        if gen_params['role'] == 'ldap_member':
            return True

        return False

    @private
    async def add_bind_interfaces(self, smbconf, ips_to_check):
        """
        smbpasswd by default connects to 127.0.0.1 as an SMB client. For this reason, localhost is added
        to the list of bind ip addresses here.
        """
        allowed_ips = await self.middleware.call('smb.bindip_choices')
        validated_bind_ips = []
        for address in ips_to_check:
            if allowed_ips.get(address):
                validated_bind_ips.append(address)
            else:
                self.logger.warning("IP address [%s] is no longer in use "
                                    "and should be removed from SMB configuration.",
                                    address)

        if validated_bind_ips:
            bindips = validated_bind_ips
            bindips.insert(0, "127.0.0.1")
            smbconf['interfaces'] = " ".join(bindips)

        smbconf['bind interfaces only'] = 'Yes'

    @private
    async def get_ds_role(self, params):
        params['ad'] = await self.middleware.call("activedirectory.config")
        params['ldap'] = await self.middleware.call("ldap.config")
        if params['ad']['enable']:
            params['role'] = 'ad_member'
        elif params['ldap']['enable'] and params['ldap']['has_samba_schema']:
            params['role'] = 'ldap_member'

    @private
    async def diff_conf_and_registry(self, data, full_check):
        """
        return differences between running configuration and a dict of smb.conf parameters.
        When full_check is True, then we diff the full running configuration.
        """
        new_conf = await self.global_to_smbconf(data)
        running_conf = (await self.middleware.call('smb.reg_globals'))['smb']

        s_keys = set(new_conf.keys())
        r_keys = set(running_conf.keys())
        intersect = s_keys.intersection(r_keys)
        return {
            'added': {x: new_conf[x] for x in s_keys - r_keys},
            'removed': {x: running_conf[x] for x in r_keys - s_keys} if full_check else {},
            'modified': {x: (new_conf[x], running_conf[x]) for x in intersect if new_conf[x] != running_conf[x]},
        }

    @private
    async def global_to_smbconf(self, data):
        """
        Convert the SMB share config into smb.conf parameters prior to
        registry insertion. Optimization in this case to _only_ set bare minimum
        parameters to reflect the specified smb service configuration.
        """
        loglevelint = LOGLEVEL_MAP.inv.get(data['loglevel'])
        loglevel = f"{loglevelint} auth_json_audit:3@/var/log/samba4/auth_audit.log"
        if data['syslog']:
            logging = f'syslog@{"3" if loglevelint > 3 else data["loglevel"]} file'
        else:
            logging = "file"

        to_set = {
            "server string": data["description"],
            "tn:netbiosname": data["netbiosname"],
            "tn:netbiosname_b": data["netbiosname_b"],
            "netbiosname": data["netbiosname_local"],
            "tn:sid": data["cifs_SID"],
            "netbios aliases": " ".join(data["netbiosalias"]),
            "server min protocol": "NT1" if data['enable_smb1'] else "SMB2_02",
            "unixcharset": data["unixcharset"],
            "syslog only": "Yes" if data["syslog"] else "No",
            "tn:fruit_enabled": "Yes" if data["aapl_extensions"] else "No",
            "local master": "Yes" if data["localmaster"] else "No",
            "guest account": data["guest"],
            "tn:admin_group": data["admin_group"] if data["admin_group"] else "",
            "create mask": data["filemask"] if data["filemask"] else "0775",
            "directory mask": data["dirmask"] if data["dirmask"] else "0775",
            "ntlm auth": "Yes" if data["ntlmv1_auth"] else "No",
            "log level": loglevel,
            "logging": logging,
        }

        await self.add_bind_interfaces(to_set, data['bindip'])
        return to_set
