import ctypes
import logging
import pathlib

from .. import winapi


class SCManager:
    def __init__(self, machine_name, database_name, access):
        self.machine_name = machine_name
        self.database_name = database_name
        self.access = access
        self.handle = None

    def open(self):
        if not self.handle:
            self.handle = winapi.OpenSCManagerW(self.machine_name, self.database_name, self.access)
        return self.handle

    def close(self):
        if self.handle:
            winapi.CloseServiceHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Service:
    logger = logging.getLogger('Service')

    def __init__(self, h_service, _close_handle=False):
        self.h_service = h_service
        self._close_handle = _close_handle

    def __del__(self):
        if self._close_handle:
            self.clean_safe()

    @classmethod
    def create(
            cls, scm,
            service_name: str,
            display_name: str,
            binary_path: str,
            desired_access=0xf01ff,  # SERVICE_ALL_ACCESS
            service_type=1,  # SERVICE_KERNEL_DRIVER
            start_type=3,  # SERVICE_DEMAND_START
            error_control=1,  # SERVICE_ERROR_NORMAL
    ):
        return cls(winapi.CreateServiceW(
            scm,
            service_name,
            display_name,
            desired_access,
            service_type,
            start_type,
            error_control,
            binary_path,
            None,  # lpLoadOrderGroup
            None,  # lpdwTagId
            None,  # lpDependencies
            None,  # lpServiceStartName
            None,  # lpPassword
        ), True)

    @classmethod
    def open(cls, scm, service_name: str, desired_access):
        return cls(winapi.OpenServiceW(scm, service_name, desired_access), True)

    def stop(self):
        assert self.h_service, 'service handle is None, is it already closed?'
        service_status = winapi.SERVICE_STATUS()
        winapi.ControlService(self.h_service, 1, ctypes.byref(service_status))
        return service_status

    def start(self):
        assert self.h_service, 'service handle is None, is it already closed?'
        winapi.StartService(self.h_service, 0, None)

    def delete(self):
        assert self.h_service, 'service handle is None, is it already closed?'
        winapi.DeleteService(self.h_service)

    def close(self):
        winapi.CloseServiceHandle(self.h_service)
        self.h_service = None

    def clean_safe(self):
        if not self.h_service:
            return
        try:
            self.stop()
        except Exception as e:
            if getattr(e, 'winerror', 0) != 1062:  # The service has not been started.
                self.logger.warning(f'stop service failed: {e}')
        try:
            self.delete()
        except Exception as e:
            if getattr(e, 'winerror', 0) != 1072:  # The specified service has been marked for deletion.
                self.logger.warning(f'delete service failed: {e}')
        try:
            self.close()
        except Exception as e:
            self.logger.warning(f'close service failed: {e}')


class DrvLoader:
    logger = logging.getLogger('DrvLoader')

    def __init__(self, service: Service, _close_handle=False):
        self.service = service
        self._close_handle = _close_handle

    def __del__(self):
        if self._close_handle:
            self.close()

    @classmethod
    def open_existing(cls, service_name):
        with SCManager(None, None, 0xf003f) as scm:
            try:
                service = Service.open(scm, service_name, 65568)
            except Exception as e:
                cls.logger.warning(f'service open: {e}')
                return None
            return cls(service, False)

    @classmethod
    def open(cls, binary_path, service_name=None, display_name=None):
        binary_path = pathlib.Path(binary_path).absolute()
        s_binary_path = str(binary_path)
        winapi.GetFileAttributesW(s_binary_path)
        service_name = service_name or binary_path.stem
        display_name = display_name or service_name
        cls.logger.debug('create service')
        with SCManager(None, None, 0xf003f) as scm:
            try:
                service = Service.open(scm, service_name, 65568)
            except Exception as e:
                cls.logger.warning(f'service open: {e}')
            else:
                service.clean_safe()
            service = Service.create(
                scm,
                service_name,
                display_name,
                s_binary_path,
                desired_access=0xf01ff,  # SERVICE_ALL_ACCESS
                service_type=1,  # SERVICE_KERNEL_DRIVER
                start_type=3,  # SERVICE_DEMAND_START
                error_control=1,  # SERVICE_ERROR_NORMAL
            )
            cls.logger.debug('start service')
            try:
                service.start()
            except Exception as e:
                if getattr(e, 'winerror', 0) == 31:
                    cls.logger.warning(f'service start: {e}')
                else:
                    raise
            cls.logger.debug('service started')
            i = cls(service, True)
            cls.instance = i
            return i

    def close(self):
        if self.service:
            self.service.clean_safe()
            self.service = None
            if DrvLoader.instance is self:
                DrvLoader.instance = None


def io_ctl_code(device_type, function, method, access):
    return ((device_type << 16) | (access << 14) | (function << 2) | method) & 0xffffffff
