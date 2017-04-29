
#include <argp.h>
#include <defines.h>

const char *argp_program_version = "madcrypt 0.0.1";
const char *argp_program_bug_address = "<aaronryool@gmail.com>";
static char doc[] = "MadCrypt - A tool for crypting / obfuscating binaries. Currently only Win32 PE files are supported.";

static char args_doc[] = "<Binary>";

static struct argp_option options[] = {
    {"verbose",  'v', 0,      0, "Produce verbose output" },
    {"silent",   's', 0,      0, "Don't produce any output" },
    {"output",   'o', "FILE", 0, "Specify output FILE, Defaults to <Binary>_new" },
    { 0 }
};



static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch(key)
    {
        case 's':
            arguments->silent = 1;
        break;
        case 'v':
            arguments->verbose = 1;
        break;
        case 'o':
            arguments->output_file = arg;
        break;

        case ARGP_KEY_ARG:
            if(state->arg_num >= 1)
                argp_usage(state);
            arguments->binary_file = arg;

        break;

        case ARGP_KEY_END:
            if(state->arg_num < 1)
                argp_usage(state);
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

void file_error(file_errors_t error)
{
    switch(error)
    {
        case OPEN:
            printf("File could not be opened...\n");
        break;
        case READ:
            printf("Problem reading file...\n");
        break;
        case WRITE:
            printf("Problem writing file...\n");
        break;
    }
    exit(-1);
}

handler_t handlers[HANDLERS];

bool handle_it(struct arguments arguments)
{
    for(int i = HANDLERS;i > 0;i--)
    {
        if(handlers[i].is_type(arguments))
            if(handlers[i].inject(arguments))
                return true;
    }
    return false;
}

int main(int argc, char **argv)
{
    struct arguments arguments;
    arguments.silent = 0;
    arguments.verbose = 0;
    arguments.output_file = 0;
    
    argp_parse (&argp, argc, argv, 0, 0, &arguments);
    
    if(arguments.output_file == 0)
    {
        arguments.output_file = malloc(strlen(arguments.binary_file) + 5);
        sprintf(arguments.output_file, "%s_new", arguments.binary_file);
    }
    
    if(! handle_it(arguments))
    {
        printf("Unsupported binary. Plesae submit a feature request or a bug report.\n");
        exit(-1);
    }
    else
        return 0;
}




