import subprocess

from middlewared.plugins.interface.netif import netif
from middlewared.service import CallError, ConfigService

from .k8s import api_client, service_accounts


class KubernetesCNIService(ConfigService):

    class Config:
        private = True
        namespace = 'k8s.cni'

    async def config(self):
        return {
            'multus': {'service_account': 'multus'},
            'kube_router': {'service_account': 'kube-router'},
        }

    async def setup_cni(self):
        kube_config = await self.middleware.call('datastore.query', 'services.kubernetes', [], {'get': True})
        config = await self.config()
        async with api_client() as (api, context):
            cni_config = kube_config['cni_config']
            for cni in config:
                if not await self.validate_cni_integrity(cni, kube_config):
                    cni_config[cni] = await service_accounts.get_service_account_details(
                        context['core_api'], config[cni]['service_account']
                    )

        await self.middleware.call(
            'datastore.update', 'services.kubernetes', kube_config['id'], {'cni_config': cni_config}
        )
        await self.middleware.call('etc.generate', 'cni')
        await self.middleware.call('service.start', 'kuberouter')

    async def validate_cni_integrity(self, cni, config=None):
        config = config or await self.middleware.call('datastore.query', 'services.kubernetes', [], {'get': True})
        return all(k in (config['cni_config'].get(cni) or {}) for k in ('ca', 'token'))

    async def kube_router_config(self):
        config = await self.middleware.call('kubernetes.config')
        return {
            'cniVersion': '0.3.0',
            'name': 'ix-net',
            'plugins': [
                {
                    'bridge': 'kube-bridge',
                    'ipam': {
                        'subnet': config['cluster_cidr'],
                        'type': 'host-local',
                    },
                    'isDefaultGateway': True,
                    'name': 'kubernetes',
                    'type': 'bridge',
                },
                {
                    'capabilities': {
                        'portMappings': True,
                        'snat': True,
                    },
                    'type': 'portmap',
                },
            ]
        }

    def cleanup_cni(self):
        # We want to remove all CNI related configuration when k8s stops
        # We will clean configuration done by kube-router now
        # Below command will cleanup iptables rules and other ipvs bits changed by kube-router
        cp = subprocess.Popen(['kube-router', '--cleanup-config'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        stderr = cp.communicate()[1]
        if cp.returncode:
            raise CallError(f'Failed to cleanup kube-router configuration: {stderr.decode()}')

        tables = netif.RoutingTable().routing_tables
        for t_name in filter(lambda t: t in tables, ('kube-router', 'kube-router-dsr')):
            table = tables[t_name]
            table.flush_routes()
            table.flush_rules()

        interfaces = netif.list_interfaces()
        for iface in map(lambda n: interfaces[n], filter(lambda n: n in interfaces, ('kube-bridge', 'kube-dummy-if'))):
            self.middleware.call_sync('interface.unconfigure', iface, [], [])
