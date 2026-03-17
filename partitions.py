import defines
import os

class PartitionList:
    def __init__(self):
        self.partition_list = [{"partition_name": "frp", "path": "frp.img"},
                               {"partition_name": "devinfo", "path": "devinfo.img"},
                               {"partition_name": "boot_a", "path": "boot.img"},
                               {"partition_name": "boot_b", "path": "boot.img"},
                               {"partition_name": "system_a", "path": "system.img"},
                               {"partition_name": "abl_a", "path": "system.img"},
                               {"partition_name": "abl_b", "path": "system.img"},
                               {"partition_name": "dtbo_a", "path": "dtbo.img"},
                               {"partition_name": "dtbo_b", "path": "dtbo.img"},
                               {"partition_name": "vbmeta_a", "path": "vbmeta.img"},
                               {"partition_name": "vbmeta_b", "path": "vbmeta.img"},
                               {"partition_name": "vendor_boot_a", "path": "vendor_boot.img"},
                               {"partition_name": "vendor_boot_b", "path": "vendor_boot.img"},
                               {"partition_name": "vbmeta_system_a", "path": "vbmeta_system.img"},
                               {"partition_name": "vbmeta_system_b", "path": "vbmeta_system.img"},
                               {"partition_name": "recovery_a", "path": "recovery.img"},
                               {"partition_name": "recovery_b", "path": "recovery.img"},
                               {"partition_name": "init_boot_a", "path": "init_boot.img"},
                               {"partition_name": "init_boot_b", "path": "init_boot.img"},
                               {"partition_name": "efisp_a", "path": "abl.pe"},
                               {"partition_name": "efisp", "path": "abl.pe"},
                               ]

        current_lba = 0
        for partition in self.partition_list:
            try:
                partition["size"] = os.path.getsize(partition["path"])
            except FileNotFoundError:
                partition["size"] = 0x10000 * defines.BLOCK_SIZE
            partition["starting_lba"] = current_lba
            partition["ending_lba"] = current_lba + partition["size"] // defines.BLOCK_SIZE - 1
            current_lba += partition["size"] // defines.BLOCK_SIZE
        
        self.total_lba = current_lba

    def get_partition_list(self):
        return self.partition_list

    def get_partition(self, partition_name):
        for partition in self.partition_list:
            if partition["partition_name"] == partition_name:
                return partition
        return None

    def __len__(self):
        return len(self.partition_list)

    def __getitem__(self, index):
        return self.partition_list[index]