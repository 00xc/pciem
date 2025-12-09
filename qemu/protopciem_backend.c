#include "qemu/osdep.h"
#include "hw/misc/protopciem_backend.h"
#include "hw/irq.h"
#include "hw/qdev-properties-system.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "ui/console.h"
#include "ui/pixel_ops.h"
#include <sys/ioctl.h>
#include <sys/mman.h>

#define FATAL_ERROR(...)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("ProtoPCIem FATAL: " __VA_ARGS__);                                                                      \
        printf("\n");                                                                                                  \
        exit(1);                                                                                                       \
    } while (0)

static int readn(int fd, void *buf, size_t n)
{
    size_t r = 0;
    while (r < n)
    {
        ssize_t m = read(fd, ((char *)buf) + r, n - r);
        if (m == 0)
            return 0;
        if (m < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        r += m;
    }
    return (int)r;
}

static int writen(int fd, const void *buf, size_t n)
{
    size_t w = 0;
    while (w < n)
    {
        ssize_t m = write(fd, ((const char *)buf) + w, n - w);
        if (m <= 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        w += m;
    }
    return (int)w;
}

static void gpu_draw_pixel(ProtoPCIemState *s, int x, int y, uint8_t r, uint8_t g, uint8_t b)
{
    if (x < 0 || x >= FB_WIDTH || y < 0 || y >= FB_HEIGHT)
    {
        return;
    }
    int idx = (y * FB_WIDTH + x) * 3;
    s->framebuffer[idx + 0] = r;
    s->framebuffer[idx + 1] = g;
    s->framebuffer[idx + 2] = b;
}

static void gpu_draw_line(ProtoPCIemState *s, int x0, int y0, int x1, int y1, uint8_t r, uint8_t g, uint8_t b)
{
    int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
    int dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
    int err = dx + dy, e2;
    for (;;)
    {
        gpu_draw_pixel(s, x0, y0, r, g, b);
        if (x0 == x1 && y0 == y1)
            break;
        e2 = 2 * err;
        if (e2 >= dy)
        {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y0 += sy;
        }
    }
}

static void gpu_clear(ProtoPCIemState *s, uint8_t r, uint8_t g, uint8_t b)
{
    if (r == g && g == b)
    {
        memset(s->framebuffer, r, FB_SIZE);
    }
    else
    {
        for (int i = 0; i < FB_WIDTH * FB_HEIGHT; i++)
        {
            s->framebuffer[i * 3 + 0] = r;
            s->framebuffer[i * 3 + 1] = g;
            s->framebuffer[i * 3 + 2] = b;
        }
    }
}

static void gpu_blit_rect(ProtoPCIemState *s, uint16_t x, uint16_t y, uint16_t width, uint16_t height,
                          const uint8_t *data)
{
    for (int j = 0; j < height; j++)
    {
        for (int i = 0; i < width; i++)
        {
            int src_idx = (j * width + i) * 3;
            gpu_draw_pixel(s, x + i, y + j, data[src_idx + 0], data[src_idx + 1], data[src_idx + 2]);
        }
    }
}

static void backend_update_display(void *opaque)
{
    ProtoPCIemState *s = opaque;
    DisplaySurface *surface = qemu_console_surface(s->con);
    if (!surface)
        return;

    uint8_t *d = surface_data(surface);
    int stride = surface_stride(surface);
    uint8_t *src = s->framebuffer;

    for (int y = 0; y < FB_HEIGHT; y++)
    {
        uint32_t *dst_row = (uint32_t *)(d + y * stride);
        uint8_t *src_row = src + y * FB_WIDTH * 3;
        for (int x = 0; x < FB_WIDTH; x++)
        {
            uint8_t r = src_row[x * 3 + 0];
            uint8_t g = src_row[x * 3 + 1];
            uint8_t b = src_row[x * 3 + 2];
            dst_row[x] = rgb_to_pixel32(r, g, b);
        }
    }
    dpy_gfx_update(s->con, 0, 0, FB_WIDTH, FB_HEIGHT);
}

static void backend_execute_command_buffer(ProtoPCIemState *s)
{
    uint8_t *p = s->cmd_buffer;
    uint8_t *end = p + s->dma_len;

    while (p < end && (p + sizeof(struct cmd_header)) <= end)
    {
        if ((uintptr_t)p % _Alignof(struct cmd_header) != 0)
        {
            FATAL_ERROR("Misaligned command");
        }

        struct cmd_header *hdr = (struct cmd_header *)p;

        if (hdr->length == 0 || (p + hdr->length) > end)
        {
            FATAL_ERROR("Corrupt command buffer");
        }

        switch (hdr->opcode)
        {
        case CMD_OP_NOP:
            break;
        case CMD_OP_CLEAR: {
            struct cmd_clear *cmd = (struct cmd_clear *)p;
            gpu_clear(s, cmd->r, cmd->g, cmd->b);
            break;
        }
        case CMD_OP_DRAW_LINE: {
            struct cmd_draw_line *cmd = (struct cmd_draw_line *)p;
            gpu_draw_line(s, cmd->x0, cmd->y0, cmd->x1, cmd->y1, cmd->r, cmd->g, cmd->b);
            break;
        }
        case CMD_OP_BLIT_RECT: {
            struct cmd_blit_rect *cmd = (struct cmd_blit_rect *)p;
            const uint8_t *data = (const uint8_t *)(cmd + 1);
            gpu_blit_rect(s, cmd->x, cmd->y, cmd->width, cmd->height, data);
            break;
        }
        default:
            printf("Unknown opcode 0x%x\n", hdr->opcode);
            exit(1);
            break;
        }

        p += hdr->length;
    }
}

static void backend_process_complete(void *opaque)
{
    ProtoPCIemState *s = opaque;
    uint64_t result = 0;

    switch (s->cmd)
    {
    case CMD_DMA_FRAME:
    case CMD_EXECUTE_CMDBUF: {
        uint64_t src_addr = ((uint64_t)s->dma_src_hi << 32) | s->dma_src_lo;
        uint32_t len = s->dma_len;

        if (s->cmd == CMD_EXECUTE_CMDBUF)
        {
            if (len > s->cmd_buffer_size)
                len = s->cmd_buffer_size;
            struct shim_dma_shared_op op;
            op.host_phys_addr = src_addr;
            op.len = len;
            if (ioctl(s->shim_fd, PCIEM_SHIM_IOCTL_DMA_READ_SHARED, &op) < 0)
            {
                perror("[QEMU] DMA_READ_SHARED failed");
            }
            else
            {
                backend_execute_command_buffer(s);
            }
        }
        else if (s->cmd == CMD_DMA_FRAME)
        {
            if (len != FB_SIZE)
            {
                FATAL_ERROR("DMA Frame size mismatch");
            }
            else
            {
                struct shim_dma_read_op op;
                op.host_phys_addr = src_addr;
                op.user_buf_addr = (uint64_t)(uintptr_t)s->framebuffer;
                op.len = len;
                if (ioctl(s->shim_fd, PCIEM_SHIM_IOCTL_DMA_READ, &op) < 0)
                {
                    perror("[QEMU] DMA_READ failed");
                }
                else
                {
                    backend_update_display(s);
                }
            }
        }

        s->status |= STATUS_DONE;
        s->status &= ~STATUS_BUSY;

        int zero = 0;
        ioctl(s->shim_fd, PCIEM_SHIM_IOCTL_RAISE_IRQ, &zero);
        return;
    }
    default:
        FATAL_ERROR("Unknown command");
        break;
    }

    s->result_lo = result & 0xFFFFFFFF;
    s->result_hi = result >> 32;
    s->status |= STATUS_DONE;
    s->status &= ~STATUS_BUSY;

    int zero = 0;
    ioctl(s->shim_fd, PCIEM_SHIM_IOCTL_RAISE_IRQ, &zero);
}

static void backend_handle_shim_event(void *opaque)
{
    ProtoPCIemState *s = PROTOPCIEM_BACKEND(opaque);
    struct shim_req req;
    struct shim_resp resp;

    int len = readn(s->shim_fd, &req, sizeof(req));
    if (len != sizeof(req))
    {
        if (len <= 0)
        {
            qemu_set_fd_handler(s->shim_fd, NULL, NULL, s);
            close(s->shim_fd);
            s->shim_fd = -1;
        }
        return;
    }
    if (req.type == 1)
    {
        uint64_t val = 0;
        switch (req.addr)
        {
        case REG_CONTROL:
            val = s->control;
            break;
        case REG_STATUS:
            val = s->status;
            break;
        case REG_CMD:
            val = s->cmd;
            break;
        case REG_DATA:
            val = s->data;
            break;
        case REG_RESULT_LO:
            val = s->result_lo;
            break;
        case REG_RESULT_HI:
            val = s->result_hi;
            break;
        case REG_DMA_SRC_LO:
            val = s->dma_src_lo;
            break;
        case REG_DMA_SRC_HI:
            val = s->dma_src_hi;
            break;
        case REG_DMA_DST_LO:
            val = s->dma_dst_lo;
            break;
        case REG_DMA_DST_HI:
            val = s->dma_dst_hi;
            break;
        case REG_DMA_LEN:
            val = s->dma_len;
            break;
        }
        resp.id = req.id;
        resp.data = val;
        writen(s->shim_fd, &resp, sizeof(resp));
    }
    else if (req.type == 2)
    {
        switch (req.addr)
        {
        case REG_CONTROL:
            s->control = req.data;
            if (req.data & 2)
            {
                s->status = 0;
                s->cmd = 0;
                s->data = 0;
                gpu_clear(s, 0, 0, 0);
                backend_update_display(s);
            }
            break;
        case REG_STATUS:
            s->status = req.data;
            break;
        case REG_CMD:
            s->cmd = req.data;
            s->status &= ~2;
            s->status |= 1;
            backend_process_complete(s);
            break;
        case REG_DATA:
            s->data = req.data;
            break;
        case REG_RESULT_LO:
            s->result_lo = req.data;
            break;
        case REG_RESULT_HI:
            s->result_hi = req.data;
            break;
        case REG_DMA_SRC_LO:
            s->dma_src_lo = req.data;
            break;
        case REG_DMA_SRC_HI:
            s->dma_src_hi = req.data;
            break;
        case REG_DMA_DST_LO:
            s->dma_dst_lo = req.data;
            break;
        case REG_DMA_DST_HI:
            s->dma_dst_hi = req.data;
            break;
        case REG_DMA_LEN:
            s->dma_len = req.data;
            break;
        }
        resp.id = req.id;
        resp.data = 0;
        writen(s->shim_fd, &resp, sizeof(resp));
    }
}

static uint64_t backend_read(void *opaque, hwaddr offset, unsigned size)
{
    return 0;
}
static void backend_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
}
static const MemoryRegionOps backend_ops = {
    .read = backend_read,
    .write = backend_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid =
        {
            .min_access_size = 4,
            .max_access_size = 8,
        },
};

static void backend_invalidate_display(void *opaque)
{
    backend_update_display(opaque);
}
static const GraphicHwOps backend_gfx_ops = {
    .invalidate = backend_invalidate_display,
    .gfx_update = backend_update_display,
};

static void protopciem_backend_realize(DeviceState *dev, Error **errp)
{
    ProtoPCIemState *s = PROTOPCIEM_BACKEND(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    memory_region_init_io(&s->iomem, OBJECT(s), &backend_ops, s, "protopciem-backend", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    s->shim_fd = open("/dev/pciem_shim", O_RDWR);
    if (s->shim_fd < 0)
    {
        perror("Failed to open /dev/pciem_shim");
        return;
    }

    s->cmd_buffer_size = CMD_BUFFER_SIZE;
    s->cmd_buffer = mmap(NULL, s->cmd_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, s->shim_fd, 0);
    if (s->cmd_buffer == MAP_FAILED)
    {
        perror("Failed to mmap shared command buffer");
        close(s->shim_fd);
        return;
    }

    qemu_set_fd_handler(s->shim_fd, backend_handle_shim_event, NULL, s);

    s->framebuffer = g_malloc0(FB_SIZE);
    s->con = graphic_console_init(dev, 0, &backend_gfx_ops, s);
    qemu_console_resize(s->con, FB_WIDTH, FB_HEIGHT);
}

static void protopciem_backend_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = protopciem_backend_realize;
    dc->desc = "ProtoPCIem Accelerator Backend";
}

static const TypeInfo protopciem_backend_info = {
    .name = TYPE_PROTOPCIEM_BACKEND,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(ProtoPCIemState),
    .class_init = protopciem_backend_class_init,
};

static void protopciem_backend_register_types(void)
{
    type_register_static(&protopciem_backend_info);
}

type_init(protopciem_backend_register_types)