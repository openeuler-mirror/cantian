import getopt
import sys


class Finder:

    """
    information of page 4
        page head info {
        page_id: 11-5	lsn: 7471652	pcn: 43	size_units: 2	size: 8192	type: pcr_heap	ext_size: 1	encrypted: 0	compressed: 0	sof_damage: 0	hard_damage: 1	next_ext: 1023-0 }
        page tail info {
        checksum: 3267	verify checksum: success	reserve: 0	pcn: 43 }
    PCR heap page information
        ...
        { first_free_dir: 16383 }
        { next 11-6 }
        { free_begin: 7236 }
        ...
    """

    page_pcr_heap = "pcr_heap"
    page_start = "information of page"
    page_id_start = "\tpage_id:"
    page_next_start = "\t{ next"

    def __init__(self, file_name, target_page_id):
        self.file_name = file_name
        self.line_array = []
        self.prev_page_id = "0-0"
        self.correct_page_id = "0-0"
        self.target_page_id = target_page_id
        self.line_num = 0

    @staticmethod
    def get_page_id(line_string):
        head_list = line_string.split(" ")
        page_id = head_list[1].split()[0]
        return page_id

    @staticmethod
    def get_type(line_string):
        head_list = line_string.split(" ")
        page_type = head_list[6].split()[0]
        return page_type

    @staticmethod
    def get_hard_damage(line_string):
        head_list = line_string.split(" ")
        hard_damage = head_list[11].split()[0]
        return hard_damage

    @staticmethod
    def get_checksum(line_string):
        tail_list = line_string.split(" ")
        checksum = tail_list[3].split()[0]
        return checksum

    @staticmethod
    def get_next(line_string):
        next_page = line_string.split(" ")[2]
        return next_page
    
    def get_line_array(self):
        with open(self.file_name, 'r') as f:
            self.line_array = f.readlines()
    
    def get_hard_damage_and_checksum(self):
        if(self.get_hard_damage(self.line_array[self.line_num]) == "0"):
            self.line_num += 2
            if (self.get_checksum(self.line_array[self.line_num]) == "success"):
                return 1
        return 0

    def handle_page(self):
        """
        find the prev_page, prev_page must satisfy:
        1. hard_damage == 0 and checksum == success
        2. type == pcr_heap
        3. next_page == target_page_id
        """
        tmp_page_id = "0-0"
        tmp_next = "0-0"
        tmp_page_type_corr_and_not_damage = 0
        while self.line_num < len(self.line_array):
            if (self.line_array[self.line_num].startswith(self.page_id_start)):
                tmp_page_id = self.get_page_id(self.line_array[self.line_num])
                if (self.get_type(self.line_array[self.line_num]) == self.page_pcr_heap and
                    self.get_hard_damage_and_checksum() == 1):
                    tmp_page_type_corr_and_not_damage = 1
            
            if (tmp_page_type_corr_and_not_damage == 1 and 
               self.line_array[self.line_num].startswith(self.page_next_start)):
                tmp_next = self.get_next(self.line_array[self.line_num])
                if (tmp_next == self.target_page_id):
                    self.prev_page_id = tmp_page_id
                    print_message("find the prev corr page: " + str(self.prev_page_id) + ", whose next is " +
                          str(self.target_page_id))
                    return
            if (self.line_array[self.line_num].startswith(self.page_start)):
                return
            self.line_num += 1
        return

    def handle_bad_page(self):
        """
        after find the prev_page, try to find the correct_next_page:
        if page_id == target_page_id and page is correct, return
        else if page_id == target_page_id but page is not correct, set target_pag_id = next_page, return
        """
        tmp_page_id = "0-0"
        tmp_find_next = 0
        while self.line_num < len(self.line_array):
            if (self.line_array[self.line_num].startswith(self.page_id_start) and
               self.get_page_id(self.line_array[self.line_num]) == self.target_page_id):
                tmp_find_next = 1
                tmp_page_id = self.get_page_id(self.line_array[self.line_num])
                if (self.get_hard_damage_and_checksum() == 1):
                    self.correct_page_id = tmp_page_id
                    print_message("the target page[" + str(tmp_page_id) + "] is correct!")
                    return
            if (tmp_find_next == 1 and self.line_array[self.line_num].startswith(self.page_next_start)):
                self.target_page_id = self.get_next(self.line_array[self.line_num])
                print_message("the bad page[" + str(tmp_page_id) + "] is bad, continue to find [" + 
                              str(tmp_page_id) + "]'s next: " + str(self.target_page_id))
                return
            if (self.line_array[self.line_num].startswith(self.page_start)):
                return
            self.line_num += 1
        return

    def get(self):
        self.get_line_array()
        while self.line_num < len(self.line_array):
            if (self.line_array[self.line_num].startswith(self.page_id_start)):
                if self.prev_page_id == "0-0":
                    self.handle_page()
                else:
                    self.handle_bad_page()
            if (self.correct_page_id != "0-0"):
                print_message("find the correct next: " + str(self.correct_page_id))
                break
            self.line_num += 1
        return


class Options(object):
    def __init__(self):
        self.file_name = ""
        self.target_page_id = ""

g_opts = Options()


def parse_parameter():
    """
    parse parameters
    -F: file_name
    -P: page_id
    """
    try:

        opts, args = getopt.getopt(sys.argv[1:], "F:P:")
        if args:
            raise Exception("Parameter input error: " + str(args[0]))

        for _key, _value in opts:
            if _key == "-F":
                g_opts.file_name = _value
            elif _key == "-P":
                g_opts.target_page_id = _value
            else:
                raise Exception("error")
                
    except getopt.GetoptError as err:
        raise Exception("Parameter input error: " + err.msg) from err
    if (g_opts.file_name == ""):
        raise Exception("please input the correct file_name.")
    if (g_opts.target_page_id == ""):
        raise Exception("please input the correct page_id.")


def print_message(msg):
    print(msg)


def main():
    """
    main entry
    """

    parse_parameter()
    finder = Finder(g_opts.file_name, g_opts.target_page_id)
    finder.get()
    if (finder.correct_page_id != "0-0"):
        print_message("please set [" + str(finder.prev_page_id) + "]'s next to [" +
                        str(finder.correct_page_id) + "].")
    elif (finder.prev_page_id == "0-0"):
        print_message("the bad page [" + str(finder.target_page_id) + "] has no prev_page.")
    else:
        print_message("Cannot find the next correct page.")
    

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print_message("Error: " + str(ex))
        exit(1)