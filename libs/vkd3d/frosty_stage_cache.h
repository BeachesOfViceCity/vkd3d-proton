/* An opt-in bounded cache for DXIL -> SPIR-V on streamed VS/PS pairs.
 * The Vulkan pipeline itself still uses the complete render state. */
struct frosty_stage_key
{
    struct d3d12_device *device;
    uint64_t root_hash, source_hash;
    struct vkd3d_shader_interface_info iface;
    struct vkd3d_shader_compile_arguments args;
    struct vkd3d_shader_parameter params[3];
    unsigned int swizzles[8];
    struct vkd3d_shader_descriptor_binding ubo, offset;
    bool debug;
};

struct frosty_stage_entry
{
    struct frosty_stage_key key;
    const struct d3d12_root_signature *owner;
    struct vkd3d_shader_code spirv;
    char *name;
    void *source;
    size_t len;
    uint64_t age;
};

static struct frosty_stage_entry frosty_stages[512];
static size_t frosty_stage_bytes;
static uint64_t frosty_stage_age;
static pthread_mutex_t frosty_stage_lock = PTHREAD_MUTEX_INITIALIZER;

static bool frosty_flag(const char *name)
{
    char value[8];
    return vkd3d_get_env_var(name, value, sizeof(value)) && !strcmp(value, "1");
}

static bool frosty_stage_key_init(struct frosty_stage_key *k, struct d3d12_pipeline_state *state,
        const struct vkd3d_shader_code *source, const struct vkd3d_shader_interface_info *i,
        const struct vkd3d_shader_compile_arguments *a, bool debug)
{
    char tmp[256];
    if (state->pipeline_type != VKD3D_PIPELINE_TYPE_GRAPHICS ||
            (i->stage != VK_SHADER_STAGE_VERTEX_BIT && i->stage != VK_SHADER_STAGE_FRAGMENT_BIT) ||
            !frosty_flag("FROSTY_SPIRV_STAGES") ||
            source->size > (16u << 20) || a->parameter_count > ARRAY_SIZE(k->params) ||
            a->output_swizzle_count > ARRAY_SIZE(k->swizzles) || i->stage_input_map || i->stage_output_map ||
            i->xfb_info || i->root_signature_blob || i->root_parameter_mappings ||
            VKD3D_CONFIG_FLAG_IS_SET(PIPELINE_LIBRARY_SANITIZE_SPIRV) ||
            VKD3D_CONFIG_FLAG_IS_SET(EXTENDED_DEBUG_UTILS) ||
            vkd3d_get_env_var("VKD3D_SHADER_OVERRIDE", tmp, sizeof(tmp)) ||
            vkd3d_get_env_var("VKD3D_SHADER_DUMP_PATH", tmp, sizeof(tmp)))
        return false;
    memset(k, 0, sizeof(*k));
    k->device = state->device;
    k->root_hash = state->root_signature->pso_compatibility_hash;
    k->source_hash = vkd3d_shader_hash(source);
    k->debug = debug;
    k->iface = *i;
    k->args = *a;
    /* The two immutable root arrays are compared by bytes on a hit. The
     * originating root removes its entries before freeing either array. */
    k->iface.bindings = NULL;
    k->iface.push_constant_buffers = NULL;
    if (i->push_constant_ubo_binding) k->ubo = *i->push_constant_ubo_binding;
    if (i->offset_buffer_binding) k->offset = *i->offset_buffer_binding;
    k->iface.push_constant_ubo_binding = NULL;
    k->iface.offset_buffer_binding = NULL;
    if (a->parameter_count) memcpy(k->params, a->parameters, a->parameter_count * sizeof(*a->parameters));
    if (a->output_swizzle_count) memcpy(k->swizzles, a->output_swizzles, a->output_swizzle_count * sizeof(*a->output_swizzles));
    k->args.parameters = NULL;
    k->args.output_swizzles = NULL;
    /* Extension list and quirk info are immutable for this device.
     * Descriptor-QA pointers, if present in this build, still have to match. */
    return true;
}

static void frosty_stage_remove(struct frosty_stage_entry *e)
{
    frosty_stage_bytes -= e->len + e->spirv.size;
    vkd3d_free(e->source);
    vkd3d_free((void *)e->spirv.code);
    vkd3d_free(e->name);
    memset(e, 0, sizeof(*e));
}

static void frosty_stage_forget_root(const struct d3d12_root_signature *root)
{
    unsigned int i;
    pthread_mutex_lock(&frosty_stage_lock);
    for (i = 0; i < ARRAY_SIZE(frosty_stages); ++i)
        if (frosty_stages[i].owner == root)
            frosty_stage_remove(&frosty_stages[i]);
    pthread_mutex_unlock(&frosty_stage_lock);
}

static struct frosty_stage_entry *frosty_stage_find(const struct frosty_stage_key *k,
        const struct d3d12_root_signature *root, const struct vkd3d_shader_code *s)
{
    struct frosty_stage_entry *e;
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(frosty_stages); ++i)
    {
        e = &frosty_stages[i];
        if (!e->owner || e->len != s->size || e->key.source_hash != k->source_hash ||
                memcmp(&e->key, k, sizeof(*k)) || memcmp(e->source, s->code, s->size))
            continue;
        if (e->owner != root && ((k->iface.binding_count && memcmp(e->owner->bindings, root->bindings,
                k->iface.binding_count * sizeof(*root->bindings))) ||
                (k->iface.push_constant_buffer_count && memcmp(e->owner->root_constants, root->root_constants,
                k->iface.push_constant_buffer_count * sizeof(*root->root_constants)))))
            continue;
        return e;
    }
    return NULL;
}

#ifdef _WIN32
#include <wincrypt.h>
struct frosty_disk_id {WCHAR path[1200]; BYTE key[32];};
struct frosty_disk_header {uint32_t version, size, name; struct vkd3d_shader_meta meta; BYTE key[32], seal[32];};
static HCRYPTPROV frosty_hash_provider;
static pthread_once_t frosty_hash_once = PTHREAD_ONCE_INIT;
static void frosty_init_hash(void)
{
    CryptAcquireContextW(&frosty_hash_provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
}
static bool frosty_hash_new(HCRYPTHASH *h)
{
    pthread_once(&frosty_hash_once, frosty_init_hash);
    return frosty_hash_provider && CryptCreateHash(frosty_hash_provider, CALG_SHA_256, 0, 0, h);
}
static bool frosty_digest(HCRYPTHASH h, BYTE *dst)
{
    DWORD n = 32;
    return CryptGetHashParam(h, HP_HASHVAL, dst, &n, 0) && n == 32;
}
static bool frosty_disk_key(struct frosty_disk_id *id, const struct frosty_stage_key *k,
        const struct d3d12_root_signature *root, const struct vkd3d_shader_code *src)
{
    const struct d3d12_device *dev = k->device;
    struct frosty_stage_key stable = *k;
    static const WCHAR hex[] = L"0123456789abcdef";
    DWORD i, n = GetEnvironmentVariableW(L"FROSTY_SPIRV_DIR", id->path, 1100);
    HCRYPTHASH h;
    bool good;
    if (!n || n >= 1100 || !frosty_hash_new(&h)) return false;
    stable.device = NULL; stable.args.target_extensions = NULL; stable.args.quirks = NULL;
#ifdef VKD3D_ENABLE_DESCRIPTOR_QA
    if (stable.iface.descriptor_qa_payload_binding || stable.iface.descriptor_qa_control_binding)
    { CryptDestroyHash(h); return false; }
#endif
#define FROSTY_HASH(p, n) ((n) == 0 || CryptHashData(h, (const BYTE *)(p), (DWORD)(n), 0))
    good = FROSTY_HASH(&stable, sizeof(stable)) &&
           FROSTY_HASH(&dev->shader_interface_key, sizeof(dev->shader_interface_key)) &&
           FROSTY_HASH(dev->device_info.properties2.properties.pipelineCacheUUID, VK_UUID_SIZE) &&
           FROSTY_HASH(k->args.target_extensions, k->args.target_extension_count * sizeof(*k->args.target_extensions)) &&
           FROSTY_HASH(root->bindings, k->iface.binding_count * sizeof(*root->bindings)) &&
           FROSTY_HASH(root->root_constants, k->iface.push_constant_buffer_count * sizeof(*root->root_constants)) &&
           FROSTY_HASH(src->code, src->size) && frosty_digest(h, id->key);
    CryptDestroyHash(h);
    if (!good) return false;
    id->path[n++] = '\\';
    for (i = 0; i < 32; ++i) {id->path[n++] = hex[id->key[i] >> 4];id->path[n++] = hex[id->key[i] & 15];}
    wcscpy(id->path+n, L".spvpack");
    return true;
}
static bool frosty_disk_seal(const struct frosty_disk_header *hdr, const void *data, const char *name, BYTE out[32])
{
    HCRYPTHASH h; bool ok;
    if (!frosty_hash_new(&h)) return false;
    ok = FROSTY_HASH(hdr, offsetof(struct frosty_disk_header, seal)) && FROSTY_HASH(data, hdr->size) &&
            FROSTY_HASH(name, hdr->name) && frosty_digest(h, out);
    CryptDestroyHash(h); return ok;
}
#undef FROSTY_HASH
static bool frosty_disk_get(const struct frosty_disk_id *id, struct vkd3d_shader_code *out, struct vkd3d_shader_code_debug *debug)
{
    struct frosty_disk_header hdr;
    LARGE_INTEGER size; BYTE seal[32]; DWORD n;
    void *data = NULL; char *name = NULL; bool success = false;
    HANDLE f = CreateFileW(id->path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    if (!ReadFile(f, &hdr, sizeof(hdr), &n, NULL) || n != sizeof(hdr) || hdr.version != 1 ||
            memcmp(hdr.key, id->key, 32) || hdr.size < 20 || hdr.size % 4 || hdr.size > (32u << 20) ||
            hdr.name > 4096 || (hdr.name && !debug) || !GetFileSizeEx(f, &size) ||
            size.QuadPart != (int64_t)(sizeof(hdr) + hdr.size + hdr.name)) goto done;
    if (!(data = vkd3d_malloc(hdr.size)) || !ReadFile(f, data, hdr.size, &n, NULL) || n != hdr.size ||
            *(const uint32_t *)data != 0x07230203) goto done;
    if (hdr.name && (!(name = vkd3d_malloc(hdr.name)) || !ReadFile(f, name, hdr.name, &n, NULL) ||
            n != hdr.name || name[n-1])) goto done;
    if (!frosty_disk_seal(&hdr, data, name, seal) || memcmp(seal, hdr.seal, 32)) goto done;
    out->code = data; out->size = hdr.size; out->meta = hdr.meta; if (debug) debug->debug_entry_point_name = name;
    success = true; data = NULL; name = NULL;
done:
    CloseHandle(f);vkd3d_free(data);vkd3d_free(name);return success;
}
static void frosty_disk_put(const struct frosty_disk_id *id, const struct vkd3d_shader_code *out, const struct vkd3d_shader_code_debug *debug)
{
    const char *name = debug ? debug->debug_entry_point_name : NULL;
    size_t namesize = name ? strlen(name)+1 : 0;
    struct frosty_disk_header hdr = {0};
    WCHAR tmp[1270];HANDLE f;DWORD n;bool ok;
    if (!out->size || out->size > (32u << 20) || namesize > 4096) return;
    hdr.version=1; hdr.size=(uint32_t)out->size; hdr.name=(uint32_t)namesize; hdr.meta=out->meta;memcpy(hdr.key,id->key,32);
    if (!frosty_disk_seal(&hdr,out->code,name,hdr.seal))return;
    swprintf(tmp,ARRAY_SIZE(tmp),L"%ls.%lu.%lu.tmp",id->path,(unsigned long)GetCurrentProcessId(),(unsigned long)GetCurrentThreadId());
    f=CreateFileW(tmp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE)return;
    ok=WriteFile(f,&hdr,sizeof(hdr),&n,NULL) && n==sizeof(hdr) && WriteFile(f,out->code,hdr.size,&n,NULL) && n==hdr.size &&
        (!hdr.name || (WriteFile(f,name,hdr.name,&n,NULL) && n==hdr.name));CloseHandle(f);
    if(!ok || !MoveFileExW(tmp,id->path,MOVEFILE_REPLACE_EXISTING))DeleteFileW(tmp);
}
#endif

static bool frosty_stage_get(const struct frosty_stage_key *k, const struct d3d12_root_signature *root,
        const struct vkd3d_shader_code *source, struct vkd3d_shader_code *out, struct vkd3d_shader_code_debug *debug)
{
    struct frosty_stage_entry *e;
    void *data = NULL;
    pthread_mutex_lock(&frosty_stage_lock);
    if ((e = frosty_stage_find(k, root, source)) && (data = vkd3d_malloc(e->spirv.size)))
    {
        if (debug && e->name && !(debug->debug_entry_point_name = vkd3d_strdup(e->name)))
        {
            vkd3d_free(data);
            data = NULL;
        }
        else
        {
            memcpy(data, e->spirv.code, e->spirv.size);
            *out = e->spirv;
            out->code = data;
            e->age = ++frosty_stage_age;
        }
    }
    pthread_mutex_unlock(&frosty_stage_lock);
    return data != NULL;
}

static void frosty_stage_put(const struct frosty_stage_key *k, const struct d3d12_root_signature *root,
        const struct vkd3d_shader_code *source, const struct vkd3d_shader_code *out,
        const struct vkd3d_shader_code_debug *debug)
{
    struct frosty_stage_entry *free_slot, *oldest;
    const size_t limit = 128u << 20;
    void *input, *spv;
    char *name = NULL;
    unsigned int i;
    if (!out->size || out->size > (32u << 20) || !(input = vkd3d_malloc(source->size)))
        return;
    if (!(spv = vkd3d_malloc(out->size)) ||
            (debug && debug->debug_entry_point_name && !(name = vkd3d_strdup(debug->debug_entry_point_name))))
        goto done;
    memcpy(input, source->code, source->size);
    memcpy(spv, out->code, out->size);
    pthread_mutex_lock(&frosty_stage_lock);
    if (frosty_stage_find(k, root, source))
        goto unlock;
    for (;;)
    {
        free_slot = NULL;
        oldest = NULL;
        for (i = 0; i < ARRAY_SIZE(frosty_stages); ++i)
        {
            struct frosty_stage_entry *e = &frosty_stages[i];
            if (!e->owner) free_slot = e;
            else if (!oldest || e->age < oldest->age) oldest = e;
        }
        if (free_slot && frosty_stage_bytes + source->size + out->size <= limit)
            break;
        if (!oldest) goto unlock;
        frosty_stage_remove(oldest);
    }
    free_slot->key = *k;
    free_slot->owner = root;
    free_slot->len = source->size;
    free_slot->source = input;
    free_slot->spirv = *out;
    free_slot->spirv.code = spv;
    free_slot->name = name;
    free_slot->age = ++frosty_stage_age;
    frosty_stage_bytes += source->size + out->size;
    input = NULL; spv = NULL; name = NULL;
unlock:
    pthread_mutex_unlock(&frosty_stage_lock);
done:
    vkd3d_free(input);
    vkd3d_free(spv);
    vkd3d_free(name);
}
